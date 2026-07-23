package aclpolicy

import (
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	tailscale "tailscale.com/client/tailscale/v2"

	"github.com/rshade/tailscale-utils/policycore"
)

// AssertionStatus is the machine-readable outcome of one policy assertion.
type AssertionStatus string

const (
	// AssertionPass means the compiled policy agreed with the assertion.
	AssertionPass AssertionStatus = "pass"
	// AssertionFail means the compiled policy disagreed with the assertion.
	AssertionFail AssertionStatus = "fail"
	// AssertionIndeterminate means the assertion could not be settled from the
	// policy file alone, so it is neither a pass nor a failure.
	AssertionIndeterminate AssertionStatus = "indeterminate"
)

// The protocols a port-only query can satisfy. Everything else (for example,
// ICMP) is a legitimate non-match rather than a parse failure.
const (
	protocolTCP       = "tcp"
	protocolUDP       = "udp"
	protocolTCPNumber = "6"
	protocolUDPNumber = "17"
)

// The selector namespaces and the autogroups this evaluator can resolve without
// control-plane state live in policycore, which owns selector resolution for
// both this tool and tailnet-audit. See policycore.AutogroupResolvable.

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
	// Indeterminate is omitted when zero so a report containing no unsettleable
	// assertion keeps the shape existing consumers already parse.
	Indeterminate int `json:"indeterminate,omitempty"`
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
// A protocol-qualified capability that names a non-port protocol (for example
// "icmp:*") is not a parse failure: it correctly grants no port access and is
// skipped in silence.
func scanRules(policy *tailscale.ACL) []RuleSkip {
	skips := make([]RuleSkip, 0)
	skips = append(skips, scanGrantRules(policy.Grants)...)
	skips = append(skips, scanACLRules(policy.ACLs)...)
	return skips
}

func scanGrantRules(grants []tailscale.Grant) []RuleSkip {
	skips := make([]RuleSkip, 0)
	for index, grant := range grants {
		for capabilityIndex, capability := range grant.IP {
			protocol, ports, found := strings.Cut(capability, ":")
			if capability == "*" {
				continue
			}
			portExpression := ports
			if !found {
				// A capability without a protocol is a bare port expression and
				// applies to both TCP and UDP. Non-port protocols must use the
				// protocol-qualified form, such as "icmp:*".
				portExpression = capability
			} else if !queryProtocol(protocol) {
				continue
			}
			if !portSpecParses(portExpression) {
				skips = append(skips, RuleSkip{
					Rule:   fmt.Sprintf("grants[%d].ip[%d]", index, capabilityIndex),
					Value:  capability,
					Reason: "port specification is not a number, range, or *",
				})
			}
		}
	}
	return skips
}

func scanACLRules(entries []tailscale.ACLEntry) []RuleSkip {
	skips := make([]RuleSkip, 0)
	for index, entry := range entries {
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
	switch assertion.Status {
	case AssertionPass:
		r.Summary.Passed++
	case AssertionIndeterminate:
		r.Summary.Indeterminate++
	case AssertionFail:
		r.Summary.Failed++
	default:
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
	// Native policy tests carry no protocol, so they ask the protocol-agnostic
	// question. A rule the evaluator cannot decide stays an error here rather
	// than becoming check's third verdict: an assertion is a pass/fail claim,
	// and answering it from an incomplete evaluation would be a guess.
	decision := policyAllows(policy, source, target, ProtocolAny)
	allowed, evidence, trace := decision.access == AccessAllow, decision.evidence, decision.trace

	// An assertion the evaluator cannot settle is reported as its own status
	// rather than aborting the run. Discarding the whole report over one
	// unresolvable rule loses every assertion already computed, and role
	// autogroups are common enough that it would fire on most real policies.
	status := AssertionFail
	switch {
	case decision.access == AccessIndeterminate:
		status = AssertionIndeterminate
	case allowed == wantAllowed:
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
		Actual:      actualText(decision.access, allowed),
		Evidence:    evidence,
		Trace:       trace,
	}, nil
}

// actualText reports what the evaluator concluded, keeping accept/deny wording
// for a settled answer so existing reports read unchanged.
func actualText(access Access, allowed bool) string {
	if access == AccessIndeterminate {
		return string(AccessIndeterminate)
	}
	return accessText(allowed)
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

	host, portText, err := splitTarget(value)
	if err != nil {
		return target{}, err
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil {
		return target{}, fmt.Errorf("destination %q has invalid port: %w", value, err)
	}
	return target{host: host, port: uint16(port)}, nil
}

func splitTarget(value string) (string, string, error) {
	if strings.HasPrefix(value, "[") {
		return splitBracketedTarget(value)
	}

	return splitUnbracketedTarget(value)
}

func splitBracketedTarget(value string) (string, string, error) {
	closing := strings.LastIndex(value, "]:")
	if closing <= 1 {
		return "", "", fmt.Errorf("destination %q must use [ipv6]:port syntax", value)
	}
	host := value[1:closing]
	if strings.ContainsAny(host, "[]") {
		return "", "", fmt.Errorf("destination %q has malformed brackets", value)
	}
	return host, value[closing+2:], nil
}

func splitUnbracketedTarget(value string) (string, string, error) {
	if strings.ContainsAny(value, "[]") {
		return "", "", fmt.Errorf("destination %q has malformed brackets", value)
	}
	if address, err := netip.ParseAddr(value); err == nil && address.Is6() {
		return "", "", fmt.Errorf("destination %q must use [ipv6]:port syntax", value)
	}
	separator := strings.LastIndexByte(value, ':')
	if separator <= 0 || separator == len(value)-1 {
		return "", "", fmt.Errorf("destination %q must have host:port syntax", value)
	}
	host := value[:separator]
	if strings.Count(host, ":") > 1 {
		return "", "", fmt.Errorf("destination %q must use [ipv6]:port syntax", value)
	}
	return host, value[separator+1:], nil
}

// reachability is the outcome of walking a policy for one query. It carries the
// three-state verdict plus the rule that decided it: the allowing rule for an
// allow, or the rule whose unevaluatable condition clouded the answer for an
// indeterminate.
type reachability struct {
	access   Access
	evidence string
	trace    []string
	rule     *RuleReference
	// gate is the bare reason an indeterminate verdict could not be settled,
	// kept separate from the rendered evidence so callers can reword it without
	// parsing prose back out of a sentence.
	gate string
}

// ruleOutcome is one rule's contribution. gate is non-empty when the rule
// matched every condition the evaluator understands and was stopped only by one
// it cannot decide from the policy file alone.
type ruleOutcome struct {
	matched  bool
	decision string
	gate     string
}

// policyAllows walks grants then legacy ACLs. A definite allow short-circuits,
// because an explicit allow settles the question no matter what else the policy
// contains. A denial is only reported once every rule has been examined and
// none was left unresolved — otherwise the answer is indeterminate, since one
// of the rules passed over might well have allowed the traffic.
func policyAllows(
	policy *tailscale.ACL,
	source string,
	destination target,
	protocol Protocol,
) reachability {
	if policy.Grants == nil && policy.ACLs == nil {
		return reachability{
			access:   AccessAllow,
			evidence: "implicit default allow policy",
			trace:    []string{"implicit default allow: no grants or ACLs section is present"},
		}
	}
	trace := make([]string, 0, len(policy.Grants)+len(policy.ACLs)+1)
	var gate string
	var gateRule *RuleReference

	record := func(kind RuleKind, index int, outcome ruleOutcome) *RuleReference {
		trace = append(trace, fmt.Sprintf("%s %d: %s", kind, index, outcome.decision))
		reference := &RuleReference{Kind: kind, Index: index}
		if outcome.gate != "" && gate == "" {
			gate, gateRule = outcome.gate, reference
		}
		return reference
	}

	for index, grant := range policy.Grants {
		outcome := grantAllows(policy, grant, source, destination, protocol)
		reference := record(RuleGrant, index, outcome)
		if outcome.matched {
			return reachability{
				access:   AccessAllow,
				evidence: fmt.Sprintf("matched grant %d", index),
				trace:    trace,
				rule:     reference,
			}
		}
	}
	for index, entry := range policy.ACLs {
		outcome := aclAllows(policy, entry, source, destination, protocol)
		reference := record(RuleACL, index, outcome)
		if outcome.matched {
			return reachability{
				access:   AccessAllow,
				evidence: fmt.Sprintf("matched acl %d", index),
				trace:    trace,
				rule:     reference,
			}
		}
	}

	if gate != "" {
		return reachability{
			access:   AccessIndeterminate,
			evidence: fmt.Sprintf("%s %d %s", gateRule.Kind, gateRule.Index, gate),
			trace:    trace,
			rule:     gateRule,
			gate:     gate,
		}
	}
	trace = append(trace, "default deny: no network grant or ACL matched")
	return reachability{
		access:   AccessDeny,
		evidence: "no network grant or ACL matched",
		trace:    trace,
	}
}

// grantAllows checks the conditions the evaluator can decide before the ones it
// cannot. A grant that fails on destination or port could never have applied,
// so it is a clean non-match even when its source names an unresolvable
// autogroup — only a grant that clears every other hurdle clouds the verdict.
func grantAllows(
	policy *tailscale.ACL,
	grant tailscale.Grant,
	source string,
	destination target,
	protocol Protocol,
) ruleOutcome {
	sourceMatched, sourceGate := anySelectorMatches(grant.Source, source, policy, source)
	if !sourceMatched && sourceGate == "" {
		return ruleOutcome{decision: "source did not match"}
	}
	destinationMatched, destinationGate := anySelectorMatches(grant.Destination, destination.host, policy, source)
	if !destinationMatched && destinationGate == "" {
		return ruleOutcome{decision: "destination did not match"}
	}
	matched, unparseable := grantIPMatches(grant.IP, destination.port, protocol)
	if !matched && !unparseable {
		// The port was decidable and did not match, so this grant is ruled out
		// whatever else on it could not be resolved. This is the narrowing rule.
		return ruleOutcome{decision: fmt.Sprintf(
			"network capability did not match port %d%s",
			destination.port,
			protocolSuffix(protocol),
		)}
	}
	gate := firstGate(
		selectorGate("source", sourceMatched, sourceGate),
		selectorGate("destination", destinationMatched, destinationGate),
		postureGate(grant.SrcPosture),
		viaGate(grant.Via),
	)
	if gate != "" {
		// Reached either because the grant matched but is gated, or because a
		// malformed capability left the port undecidable. A capability that
		// could not be parsed cannot rule the grant out, so it must not turn an
		// unresolved condition into a confident denial.
		return ruleOutcome{decision: "could not evaluate: " + gate, gate: gate}
	}
	if !matched {
		return ruleOutcome{decision: "network capability could not be parsed"}
	}
	return ruleOutcome{matched: true, decision: "source, destination, and network capability matched"}
}

func aclAllows(
	policy *tailscale.ACL,
	entry tailscale.ACLEntry,
	source string,
	destination target,
	protocol Protocol,
) ruleOutcome {
	sources := entry.Source
	if len(sources) == 0 {
		sources = entry.Users
	}
	sourceMatched, sourceGate := anySelectorMatches(sources, source, policy, source)
	if !sourceMatched && sourceGate == "" {
		return ruleOutcome{decision: "source did not match"}
	}
	if entry.Action != "" && entry.Action != "accept" {
		return ruleOutcome{decision: fmt.Sprintf("action %q is not accept", entry.Action)}
	}
	if entry.Protocol != "" && !capabilityProtocolMatches(entry.Protocol, protocol) {
		return ruleOutcome{decision: fmt.Sprintf("protocol %q did not match", entry.Protocol)}
	}
	destinations := entry.Destination
	if len(destinations) == 0 {
		destinations = entry.Ports
	}
	destinationMatched, unparseable, destinationGate := aclDestinationMatches(
		destinations, destination, policy, source,
	)
	if !destinationMatched && !unparseable && destinationGate == "" {
		// Decidably not this rule's destination, so it is ruled out regardless
		// of anything unresolved on its source. This is the narrowing rule.
		return ruleOutcome{decision: "destination or port did not match"}
	}
	gate := firstGate(
		selectorGate("source", sourceMatched, sourceGate),
		selectorGate("destination", destinationMatched, destinationGate),
		postureGate(entry.SourcePosture),
	)
	if gate != "" {
		// See grantAllows: a destination that could not be parsed leaves the
		// rule undecided, so it must not swallow an unresolved condition.
		return ruleOutcome{decision: "could not evaluate: " + gate, gate: gate}
	}
	if !destinationMatched {
		return ruleOutcome{decision: "destination could not be parsed"}
	}
	return ruleOutcome{matched: true, decision: "source, destination, and port matched"}
}

// protocolSuffix names the protocol in a trace line only when the query was
// narrowed to one, so the protocol-agnostic default reads the way it always has.
func protocolSuffix(protocol Protocol) string {
	if protocol == ProtocolAny || protocol == "" {
		return ""
	}
	return " for protocol " + string(protocol)
}

func firstGate(gates ...string) string {
	for _, gate := range gates {
		if gate != "" {
			return gate
		}
	}
	return ""
}

func selectorGate(field string, matched bool, selector string) string {
	if matched || selector == "" {
		return ""
	}
	return fmt.Sprintf("%s selector %q cannot be resolved from the policy file", field, selector)
}

// postureGate and viaGate keep the wording of the errors these conditions used
// to raise, so EvaluateTests still reports them exactly as it always has.
func postureGate(posture []string) string {
	if len(posture) == 0 {
		return ""
	}
	return "uses unsupported srcPosture"
}

func viaGate(via []string) string {
	if len(via) == 0 {
		return ""
	}
	return "uses unsupported via routing"
}

// anySelectorMatches reports whether any selector matches query, and when none
// does, the first selector whose meaning the evaluator could not determine.
//
// Resolution itself lives in policycore so this tool and tailnet-audit cannot
// drift on what one policy means; this adapter only reshapes the three-state
// answer into the (matched, gate) pair the rule walkers consume.
func anySelectorMatches(
	selectors []string,
	query string,
	policy *tailscale.ACL,
	source string,
) (bool, string) {
	match, unresolved := policycore.AnySelectorMatchesTri(selectors, query, policy, source)
	return match == policycore.Matched, unresolved
}

// grantIPMatches reports whether any network capability covers port, and
// whether one was skipped because its port expression did not parse. See
// scanRules for why an unparseable element is worth distinguishing.
func grantIPMatches(capabilities []string, port uint16, query Protocol) (bool, bool) {
	unparseable := false
	for _, capability := range capabilities {
		if capability == "*" {
			return true, false
		}
		protocol, ports, found := strings.Cut(capability, ":")
		if !found {
			// A capability without a protocol is a bare port expression and
			// applies to every protocol, so narrowing the query cannot exclude it.
			hit, parsed := portSpecMatches(capability, port)
			switch {
			case !parsed:
				unparseable = true
			case hit:
				return true, false
			}
			continue
		}
		if !capabilityProtocolMatches(protocol, query) {
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

// queryProtocol reports whether protocol can satisfy a reachability question
// that does not name a protocol. This mirrors native policy tests: an omitted
// protocol asks whether either TCP or UDP is allowed.
func queryProtocol(protocol string) bool {
	return protocol == protocolTCP || protocol == protocolUDP ||
		protocol == protocolTCPNumber || protocol == protocolUDPNumber
}

// capabilityProtocolMatches reports whether a rule's protocol token can satisfy
// a query for the given protocol. Both the named and numeric spellings of TCP
// and UDP are recognized; any other protocol carries no port access and so can
// never satisfy a port-based question.
func capabilityProtocolMatches(token string, query Protocol) bool {
	var named Protocol
	switch token {
	case protocolTCP, protocolTCPNumber:
		named = ProtocolTCP
	case protocolUDP, protocolUDPNumber:
		named = ProtocolUDP
	default:
		return false
	}
	return query == ProtocolAny || query == "" || query == named
}

// aclDestinationMatches reports whether any destination covers query, whether
// one was skipped because it did not parse, and the first selector whose
// meaning the evaluator could not determine. See scanRules for why an
// unparseable element is worth distinguishing.
//
// A legacy destination is one "selector:port" string, so the port is checked
// first: an entry the port rules out could never have applied, and must stay a
// clean non-match rather than clouding the verdict with its selector.
func aclDestinationMatches(
	destinations []string,
	query target,
	policy *tailscale.ACL,
	source string,
) (bool, bool, string) {
	unparseable, unresolved := false, ""
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
		if !hit {
			continue
		}
		if policycore.SelectorMatches(host, query.host, policy, source) {
			return true, false, ""
		}
		if unresolved == "" && !policycore.AutogroupResolvable(host, query.host) {
			unresolved = host
		}
	}
	return false, unparseable, unresolved
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
		case start > end:
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
