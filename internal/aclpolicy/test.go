package aclpolicy

import (
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	tailscale "tailscale.com/client/tailscale/v2"
)

// AssertionStatus is the machine-readable outcome of one policy assertion.
type AssertionStatus string

const (
	// AssertionPass means the compiled policy agreed with the assertion.
	AssertionPass AssertionStatus = "pass"
	// AssertionFail means the compiled policy disagreed with the assertion.
	AssertionFail AssertionStatus = "fail"
)

// The port-carrying protocols. Everything else (icmp, numeric protocols) grants
// no port access, which is a legitimate non-match rather than a parse failure.
const (
	protocolTCP = "tcp"
	protocolUDP = "udp"
)

// AssertionResult describes one accept or deny destination from a policy test.
// IDs are derived from the policy's array indexes and are stable for unchanged
// input, which makes them useful to CI and agent consumers. They always use the
// canonical accept and deny spelling, so a test written with the legacy allow
// key still reports as tests[i].accept[j]: the ID is a stable identifier, not a
// literal path into the source file.
type AssertionResult struct {
	ID          string          `json:"id"`
	Status      AssertionStatus `json:"status"`
	TestIndex   int             `json:"test_index"`
	Expectation string          `json:"expectation"`
	Source      string          `json:"source"`
	Destination string          `json:"destination"`
	Expected    string          `json:"expected"`
	Actual      string          `json:"actual"`
	Evidence    string          `json:"evidence"`
	Trace       []string        `json:"trace"`
}

// TestSummary contains aggregate counts for a policy test run.
type TestSummary struct {
	Total  int `json:"total"`
	Passed int `json:"passed"`
	Failed int `json:"failed"`
}

// RuleSkip names one policy rule element the evaluator cannot parse. Such an
// element can never match, so any verdict reached alongside it may be wrong —
// the traffic could well be allowed by the rule the author meant to write.
// TestOptions.Strict turns these into an error instead of a recorded skip.
type RuleSkip struct {
	Rule   string `json:"rule"`
	Value  string `json:"value"`
	Reason string `json:"reason"`
}

func (s RuleSkip) String() string {
	return fmt.Sprintf("%s %q: %s", s.Rule, s.Value, s.Reason)
}

// TestOptions configures EvaluateTests.
type TestOptions struct {
	// Strict rejects a policy containing any rule element the evaluator cannot
	// parse, rather than reporting verdicts computed while ignoring it.
	Strict bool
}

// TestReport is the pure, deterministic result of evaluating policy.Tests.
type TestReport struct {
	Assertions []AssertionResult `json:"assertions"`
	Skipped    []RuleSkip        `json:"skipped,omitempty"`
	Summary    TestSummary       `json:"summary"`
}

// EvaluateTests evaluates the policy's native network accept/deny assertions
// against its grants and legacy ACL rules without contacting the control plane.
//
// Rule syntax is scanned once, before any assertion runs, so an unparseable
// rule is reported the same way no matter which assertions the policy declares.
func EvaluateTests(policy *tailscale.ACL, opts TestOptions) (TestReport, error) {
	skipped := scanRules(policy)
	if opts.Strict && len(skipped) != 0 {
		return TestReport{}, fmt.Errorf("%s (%d unparseable rule(s) in strict mode)", skipped[0], len(skipped))
	}
	report := TestReport{Assertions: make([]AssertionResult, 0), Skipped: skipped}
	for testIndex, test := range policy.Tests {
		source, accept, err := normalizeTest(testIndex, test)
		if err != nil {
			return TestReport{}, err
		}
		if len(test.SrcPostureAttrs) != 0 {
			return TestReport{}, fmt.Errorf(
				"tests[%d]: srcPostureAttrs is not supported by the local evaluator",
				testIndex,
			)
		}

		for assertionIndex, destination := range accept {
			assertion, assertionErr := evaluateAssertion(
				policy, testIndex, assertionIndex, "accept", source, destination, true,
			)
			if assertionErr != nil {
				return TestReport{}, assertionErr
			}
			report.add(assertion)
		}
		for assertionIndex, destination := range test.Deny {
			assertion, assertionErr := evaluateAssertion(
				policy, testIndex, assertionIndex, "deny", source, destination, false,
			)
			if assertionErr != nil {
				return TestReport{}, assertionErr
			}
			report.add(assertion)
		}
	}
	return report, nil
}

// scanRules reports every rule element whose syntax the evaluator cannot make
// sense of — an ACL destination missing its port, or a port expression that is
// not a number, range, or "*". It deliberately runs over the whole policy
// rather than along the matching path, so the answer does not depend on which
// assertions happen to reach which rule.
//
// A capability that names a non-port protocol (for example "icmp") is not a
// parse failure: it correctly grants no port access and is skipped in silence.
func scanRules(policy *tailscale.ACL) []RuleSkip {
	skips := make([]RuleSkip, 0)
	for index, grant := range policy.Grants {
		for capabilityIndex, capability := range grant.IP {
			protocol, ports, found := strings.Cut(capability, ":")
			if capability == "*" || !found || (protocol != protocolTCP && protocol != protocolUDP) {
				continue
			}
			if !portSpecParses(ports) {
				skips = append(skips, RuleSkip{
					Rule:   fmt.Sprintf("grants[%d].ip[%d]", index, capabilityIndex),
					Value:  capability,
					Reason: "port specification is not a number, range, or *",
				})
			}
		}
	}
	for index, entry := range policy.ACLs {
		field, destinations := "dst", entry.Destination
		if len(destinations) == 0 {
			field, destinations = "ports", entry.Ports
		}
		for destinationIndex, destination := range destinations {
			reason := scanDestination(destination)
			if reason == "" {
				continue
			}
			skips = append(skips, RuleSkip{
				Rule:   fmt.Sprintf("acls[%d].%s[%d]", index, field, destinationIndex),
				Value:  destination,
				Reason: reason,
			})
		}
	}
	return skips
}

// scanDestination reports why an ACL destination cannot be evaluated, or "" if
// it can. Because the selector and port are split at the final colon, a missing
// port ("tag:web") and a malformed one ("tag:web:https") are indistinguishable
// without a list of namespace prefixes that Tailscale is free to extend, so the
// one message covers both readings.
func scanDestination(destination string) string {
	_, ports, ok := splitSelectorPort(destination)
	if !ok || !portSpecParses(ports) {
		return "destination has no valid port (want host:443, host:80-443, or host:*)"
	}
	return ""
}

func normalizeTest(index int, test tailscale.ACLTest) (string, []string, error) {
	if test.Source != "" && test.User != "" {
		return "", nil, fmt.Errorf("tests[%d]: only one of src or user may be set", index)
	}
	source := test.Source
	if source == "" {
		source = test.User
	}
	if source == "" {
		return "", nil, fmt.Errorf("tests[%d]: src is required", index)
	}
	if len(test.Accept) != 0 && len(test.Allow) != 0 {
		return "", nil, fmt.Errorf("tests[%d]: only one of accept or allow may be set", index)
	}
	accept := test.Accept
	if len(accept) == 0 {
		accept = test.Allow
	}
	return source, accept, nil
}

func (r *TestReport) add(assertion AssertionResult) {
	r.Assertions = append(r.Assertions, assertion)
	r.Summary.Total++
	if assertion.Status == AssertionPass {
		r.Summary.Passed++
	} else {
		r.Summary.Failed++
	}
}

func evaluateAssertion(
	policy *tailscale.ACL,
	testIndex, assertionIndex int,
	expectation, source, destination string,
	wantAllowed bool,
) (AssertionResult, error) {
	target, err := parseTarget(destination)
	if err != nil {
		return AssertionResult{}, fmt.Errorf("tests[%d].%s[%d]: %w", testIndex, expectation, assertionIndex, err)
	}
	allowed, evidence, trace, err := policyAllows(policy, source, target)
	if err != nil {
		return AssertionResult{}, fmt.Errorf("tests[%d].%s[%d]: %w", testIndex, expectation, assertionIndex, err)
	}

	status := AssertionFail
	if allowed == wantAllowed {
		status = AssertionPass
	}
	return AssertionResult{
		ID:          fmt.Sprintf("tests[%d].%s[%d]", testIndex, expectation, assertionIndex),
		Status:      status,
		TestIndex:   testIndex,
		Expectation: expectation,
		Source:      source,
		Destination: destination,
		Expected:    accessText(wantAllowed),
		Actual:      accessText(allowed),
		Evidence:    evidence,
		Trace:       trace,
	}, nil
}

func accessText(allowed bool) string {
	if allowed {
		return "accept"
	}
	return "deny"
}

type target struct {
	host string
	port uint16
}

func parseTarget(value string) (target, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return target{}, errors.New("destination is empty")
	}

	var host, portText string
	if strings.HasPrefix(value, "[") {
		closing := strings.LastIndex(value, "]:")
		if closing < 0 {
			return target{}, fmt.Errorf("destination %q must use [ipv6]:port syntax", value)
		}
		host, portText = value[1:closing], value[closing+2:]
	} else {
		separator := strings.LastIndexByte(value, ':')
		if separator <= 0 || separator == len(value)-1 {
			return target{}, fmt.Errorf("destination %q must have host:port syntax", value)
		}
		host, portText = value[:separator], value[separator+1:]
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil {
		return target{}, fmt.Errorf("destination %q has invalid port: %w", value, err)
	}
	return target{host: host, port: uint16(port)}, nil
}

func policyAllows(policy *tailscale.ACL, source string, destination target) (bool, string, []string, error) {
	trace := make([]string, 0, len(policy.Grants)+len(policy.ACLs)+1)
	for index, grant := range policy.Grants {
		matched, decision, err := grantAllows(policy, grant, source, destination)
		if err != nil {
			return false, "", nil, fmt.Errorf("matching grant %d: %w", index, err)
		}
		trace = append(trace, fmt.Sprintf("grant %d: %s", index, decision))
		if matched {
			return true, fmt.Sprintf("matched grant %d", index), trace, nil
		}
	}

	for index, entry := range policy.ACLs {
		matched, decision, err := aclAllows(policy, entry, source, destination)
		if err != nil {
			return false, "", nil, fmt.Errorf("matching acl %d: %w", index, err)
		}
		trace = append(trace, fmt.Sprintf("acl %d: %s", index, decision))
		if matched {
			return true, fmt.Sprintf("matched acl %d", index), trace, nil
		}
	}

	trace = append(trace, "default deny: no network grant or ACL matched")
	return false, "no network grant or ACL matched", trace, nil
}

func grantAllows(
	policy *tailscale.ACL,
	grant tailscale.Grant,
	source string,
	destination target,
) (bool, string, error) {
	if !anySelectorMatches(grant.Source, source, policy, source) {
		return false, "source did not match", nil
	}
	if !anySelectorMatches(grant.Destination, destination.host, policy, source) {
		return false, "destination did not match", nil
	}
	if matched, unparseable := grantIPMatches(grant.IP, destination.port); !matched {
		if unparseable {
			return false, "network capability could not be parsed", nil
		}
		return false, fmt.Sprintf(
			"network capability did not match port %d",
			destination.port,
		), nil
	}
	if len(grant.SrcPosture) != 0 {
		return false, "", errors.New("uses unsupported srcPosture")
	}
	if len(grant.Via) != 0 {
		return false, "", errors.New("uses unsupported via routing")
	}
	return true, "source, destination, and network capability matched", nil
}

func aclAllows(
	policy *tailscale.ACL,
	entry tailscale.ACLEntry,
	source string,
	destination target,
) (bool, string, error) {
	sources := entry.Source
	if len(sources) == 0 {
		sources = entry.Users
	}
	if !anySelectorMatches(sources, source, policy, source) {
		return false, "source did not match", nil
	}
	if entry.Action != "" && entry.Action != "accept" {
		return false, fmt.Sprintf("action %q is not accept", entry.Action), nil
	}
	if entry.Protocol != "" && entry.Protocol != protocolTCP && entry.Protocol != protocolUDP {
		return false, fmt.Sprintf("protocol %q did not match", entry.Protocol), nil
	}
	destinations := entry.Destination
	if len(destinations) == 0 {
		destinations = entry.Ports
	}
	if matched, unparseable := aclDestinationMatches(destinations, destination, policy, source); !matched {
		if unparseable {
			return false, "destination could not be parsed", nil
		}
		return false, "destination or port did not match", nil
	}
	if len(entry.SourcePosture) != 0 {
		return false, "", errors.New("uses unsupported srcPosture")
	}
	return true, "source, destination, and port matched", nil
}

func anySelectorMatches(selectors []string, query string, policy *tailscale.ACL, source string) bool {
	for _, selector := range selectors {
		if selectorMatches(selector, query, policy, source, make(map[string]bool)) {
			return true
		}
	}
	return false
}

func selectorMatches(
	selector, query string,
	policy *tailscale.ACL,
	source string,
	seenGroups map[string]bool,
) bool {
	if directSelectorMatches(selector, query, policy, source) {
		return true
	}
	if groupSelectorMatches(selector, query, policy, source, seenGroups) {
		return true
	}
	return addressSelectorsMatch(selector, query, policy)
}

func directSelectorMatches(selector, query string, policy *tailscale.ACL, source string) bool {
	return selector == "*" || selector == query ||
		(selector == "autogroup:self" && query == source) ||
		(selector == "autogroup:member" && looksLikeUser(query)) ||
		(selector == "autogroup:internet" && isPublicAddress(query, policy))
}

func groupSelectorMatches(
	selector, query string,
	policy *tailscale.ACL,
	source string,
	seenGroups map[string]bool,
) bool {
	members, ok := policy.Groups[selector]
	if !ok || seenGroups[selector] {
		return false
	}
	seenGroups[selector] = true
	defer delete(seenGroups, selector)
	for _, member := range members {
		if selectorMatches(member, query, policy, source, seenGroups) {
			return true
		}
	}
	return false
}

func addressSelectorsMatch(selector, query string, policy *tailscale.ACL) bool {
	selectorValues := expandAddressSelector(selector, policy)
	queryValues := expandAddressSelector(query, policy)
	for _, selectorValue := range selectorValues {
		for _, queryValue := range queryValues {
			if addressContains(selectorValue, queryValue) {
				return true
			}
		}
	}
	return false
}

func looksLikeUser(selector string) bool {
	return strings.Contains(selector, "@") && !strings.HasPrefix(selector, "group:")
}

func expandAddressSelector(selector string, policy *tailscale.ACL) []string {
	if address, ok := policy.Hosts[selector]; ok {
		return []string{address}
	}
	if values, ok := policy.IPSets[selector]; ok {
		return values
	}
	return []string{selector}
}

func addressContains(selector, query string) bool {
	selectorPrefix, selectorErr := netip.ParsePrefix(selector)
	queryAddress, queryErr := netip.ParseAddr(strings.Trim(query, "[]"))
	if selectorErr == nil && queryErr == nil {
		return selectorPrefix.Contains(queryAddress)
	}
	selectorAddress, selectorAddressErr := netip.ParseAddr(strings.Trim(selector, "[]"))
	return selectorAddressErr == nil && queryErr == nil && selectorAddress == queryAddress
}

func isPublicAddress(selector string, policy *tailscale.ACL) bool {
	for _, value := range expandAddressSelector(selector, policy) {
		address, err := netip.ParseAddr(strings.Trim(value, "[]"))
		if err != nil {
			continue
		}
		if address.IsGlobalUnicast() && !address.IsPrivate() && !isTailscaleAddress(address) {
			return true
		}
	}
	return false
}

func isTailscaleAddress(address netip.Addr) bool {
	tailscaleIPv4 := netip.MustParsePrefix("100.64.0.0/10")
	tailscaleIPv6 := netip.MustParsePrefix("fd7a:115c:a1e0::/48")
	return tailscaleIPv4.Contains(address) || tailscaleIPv6.Contains(address)
}

// grantIPMatches reports whether any network capability covers port, and
// whether one was skipped because its port expression did not parse. See
// scanRules for why an unparseable element is worth distinguishing.
func grantIPMatches(capabilities []string, port uint16) (bool, bool) {
	unparseable := false
	for _, capability := range capabilities {
		if capability == "*" {
			return true, false
		}
		protocol, ports, found := strings.Cut(capability, ":")
		if !found || (protocol != protocolTCP && protocol != protocolUDP) {
			continue
		}
		hit, parsed := portSpecMatches(ports, port)
		switch {
		case !parsed:
			unparseable = true
		case hit:
			return true, false
		}
	}
	return false, unparseable
}

// aclDestinationMatches reports whether any destination covers query, and
// whether one was skipped because it did not parse. See scanRules for why an
// unparseable element is worth distinguishing.
func aclDestinationMatches(
	destinations []string,
	query target,
	policy *tailscale.ACL,
	source string,
) (bool, bool) {
	unparseable := false
	for _, destination := range destinations {
		host, ports, ok := splitSelectorPort(destination)
		if !ok {
			unparseable = true
			continue
		}
		hit, parsed := portSpecMatches(ports, query.port)
		if !parsed {
			unparseable = true
			continue
		}
		if hit && selectorMatches(host, query.host, policy, source, make(map[string]bool)) {
			return true, false
		}
	}
	return false, unparseable
}

func splitSelectorPort(value string) (string, string, bool) {
	if strings.HasPrefix(value, "[") {
		closing := strings.LastIndex(value, "]:")
		if closing < 0 || closing+2 == len(value) {
			return "", "", false
		}
		return value[1:closing], value[closing+2:], true
	}
	separator := strings.LastIndexByte(value, ':')
	if separator <= 0 || separator == len(value)-1 {
		return "", "", false
	}
	return value[:separator], value[separator+1:], true
}

// portSpecMatches reports whether port satisfies a Tailscale port expression
// ("*", "443", "80,443", "8000-8080") and whether every part of that expression
// parsed. A part that does not parse can never match, so callers must not
// report the result as "did not match" without checking parsed first.
func portSpecMatches(spec string, port uint16) (bool, bool) {
	if spec == "*" {
		return true, true
	}
	matched, parsed := false, true
	for part := range strings.SplitSeq(spec, ",") {
		startText, endText, hasRange := strings.Cut(part, "-")
		if !hasRange {
			value, err := strconv.ParseUint(part, 10, 16)
			switch {
			case err != nil:
				parsed = false
			case uint16(value) == port:
				matched = true
			}
			continue
		}
		start, startErr := strconv.ParseUint(startText, 10, 16)
		end, endErr := strconv.ParseUint(endText, 10, 16)
		switch {
		case startErr != nil || endErr != nil:
			parsed = false
		case start <= uint64(port) && uint64(port) <= end:
			matched = true
		}
	}
	return matched, parsed
}

func portSpecParses(spec string) bool {
	_, parsed := portSpecMatches(spec, 0)
	return parsed
}
