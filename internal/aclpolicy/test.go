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
	protocolTCP        = "tcp"
	protocolUDP        = "udp"
	protocolSCTP       = "sctp"
	protocolTCPNumber  = 6
	protocolUDPNumber  = 17
	protocolSCTPNumber = 132
)

// The selector namespaces and the autogroups this evaluator can resolve without
// control-plane state live in policycore, which owns selector resolution for
// both this tool and tailnet-audit. See policycore.Matcher.MatchesTri.

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

// RuleSkip names one policy rule element the evaluator cannot parse. The
// element might have matched if understood, so an assertion whose narrowed
// evaluation path reaches it is indeterminate. TestOptions.Strict instead
// rejects the whole policy before evaluating any assertion.
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
	// Roster maps a lowercased login to its tailnet role, resolving the role
	// autogroups the policy file alone cannot decide. Build it with
	// policycore.ParseRoster, which owns the lowercasing this lookup requires.
	//
	// A non-nil Roster asserts the roster is complete and authoritative; see
	// ReachabilityOptions.Roster for why this is one nilable map rather than a
	// map beside a HaveRoles bool.
	Roster map[string]tailscale.UserRole
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
// Skipped is therefore policy-scoped; an indeterminate assertion is separately
// path-scoped and is reported only when its evaluation reaches such a defect.
func EvaluateTests(policy *tailscale.ACL, opts TestOptions) (TestReport, error) {
	// HaveExternalTailnets stays false: this loader does not parse
	// externalTailnets, so a cross-tailnet selector stays Unresolvable.
	matcher := policycore.Matcher{
		Policy:    &policycore.Policy{ACL: policy},
		Roles:     opts.Roster,
		HaveRoles: opts.Roster != nil,
	}
	skipped := scanRules(matcher)
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
				matcher, testIndex, assertionIndex, string(TestAccept), source, destination, true,
			)
			if assertionErr != nil {
				return TestReport{}, assertionErr
			}
			report.add(assertion)
		}
		for assertionIndex, destination := range test.Deny {
			assertion, assertionErr := evaluateAssertion(
				matcher, testIndex, assertionIndex, string(TestDeny), source, destination, false,
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
func scanRules(matcher policycore.Matcher) []RuleSkip {
	skips := make([]RuleSkip, 0)
	skips = append(skips, scanGrantRules(matcher.Policy.Grants)...)
	skips = append(skips, scanACLRules(matcher.Policy.ACLs)...)
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
			switch {
			case !found:
				// A capability without a protocol is a bare port expression and
				// applies to both TCP and UDP. Non-port protocols must use the
				// protocol-qualified form, such as "icmp:*".
				portExpression = capability
			case capabilityAllProtocols(protocol):
				// The wildcard spellings are legal here even though acls[].proto
				// rejects them; only the port half still has to parse. Keep this
				// ahead of the knownIPProtocol arm, which does not accept them.
			case !knownIPProtocol(protocol):
				skips = append(skips, RuleSkip{
					Rule:   fmt.Sprintf("grants[%d].ip[%d]", index, capabilityIndex),
					Value:  capability,
					Reason: "protocol is not a known name or number",
				})
				continue
			case !queryProtocol(protocol):
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
		if entry.Protocol != "" && !knownIPProtocol(entry.Protocol) {
			skips = append(skips, RuleSkip{
				Rule:   fmt.Sprintf("acls[%d].proto", index),
				Value:  entry.Protocol,
				Reason: "protocol is not a known name or number",
			})
		}
		field, destinations := policyDestinationField, entry.Destination
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
	matcher policycore.Matcher,
	testIndex, assertionIndex int,
	expectation, source, destination string,
	wantAllowed bool,
) (AssertionResult, error) {
	target, err := parseTarget(destination)
	if err != nil {
		return AssertionResult{}, fmt.Errorf("tests[%d].%s[%d]: %w", testIndex, expectation, assertionIndex, err)
	}
	// Native policy tests carry no protocol, so they ask the protocol-agnostic
	// question. A rule the evaluator cannot decide becomes the assertion's
	// third verdict; answering accept or deny from an incomplete walk would be
	// a guess.
	decision := policyAllows(matcher, source, target, ProtocolAny)
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
		return string(TestAccept)
	}
	return string(TestDeny)
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
	matcher policycore.Matcher,
	source string,
	destination target,
	protocol Protocol,
) reachability {
	policy := matcher.Policy
	if policy.Grants == nil && policy.ACLs == nil {
		// An absent grants/acls section is Tailscale's implicit allow policy.
		// An explicitly empty section is non-nil and therefore reaches the
		// default deny below; preserve that JSON nil-ness distinction.
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
		outcome := grantAllows(matcher, grant, source, destination, protocol)
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
		outcome := aclAllows(matcher, entry, source, destination, protocol)
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
	matcher policycore.Matcher,
	grant tailscale.Grant,
	source string,
	destination target,
	protocol Protocol,
) ruleOutcome {
	sourceMatched, sourceGate := anySelectorMatches(grant.Source, source, matcher, source)
	if !sourceMatched && sourceGate == "" {
		return ruleOutcome{decision: "source did not match"}
	}
	destinationMatched, destinationGate := anySelectorMatches(
		grant.Destination, destination.host, matcher, source,
	)
	if !destinationMatched && destinationGate == "" {
		return ruleOutcome{decision: "destination did not match"}
	}
	ip := grantIPMatches(grant.IP, destination.port, protocol)
	if !ip.matched && !ip.unparseable {
		// The capability was decidable and did not match, so this grant is ruled
		// out whatever else on it could not be resolved. This is the narrowing
		// rule. Name whichever field decided it: blaming the port for a protocol
		// mismatch sends a reader to change a port range that was never wrong.
		if ip.protocolMiss != "" {
			return ruleOutcome{decision: fmt.Sprintf(
				"network capability port %d matched but protocol %q did not",
				destination.port,
				ip.protocolMiss,
			)}
		}
		if ip.defaultProtosMiss {
			return ruleOutcome{decision: fmt.Sprintf(
				"network capability port %d matched but its default protocol set does not cover %s",
				destination.port,
				protocol,
			)}
		}
		return ruleOutcome{decision: fmt.Sprintf(
			"network capability did not match port %d%s",
			destination.port,
			protocolSuffix(protocol),
		)}
	}
	gate := firstGate(
		selectorGate("source", sourceMatched, sourceGate, source),
		selectorGate("destination", destinationMatched, destinationGate, destination.host),
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
	if !ip.matched {
		parseGate := "network capability could not be parsed"
		return ruleOutcome{decision: "could not evaluate: " + parseGate, gate: parseGate}
	}
	return ruleOutcome{matched: true, decision: "source, destination, and network capability matched"}
}

func aclAllows(
	matcher policycore.Matcher,
	entry tailscale.ACLEntry,
	source string,
	destination target,
	protocol Protocol,
) ruleOutcome {
	sources := entry.Source
	if len(sources) == 0 {
		sources = entry.Users
	}
	sourceMatched, sourceGate := anySelectorMatches(sources, source, matcher, source)
	if !sourceMatched && sourceGate == "" {
		return ruleOutcome{decision: "source did not match"}
	}
	if entry.Action != "" && entry.Action != string(TestAccept) {
		return ruleOutcome{decision: fmt.Sprintf("action %q is not accept", entry.Action)}
	}
	protocolGate := ""
	switch {
	case entry.Protocol == "":
		// An omitted proto is compiled with no IPProto, which the packet filter
		// expands to the same default set as a proto-0 capability. SCTP is
		// outside it, so an entry that names no protocol cannot answer for SCTP.
		if !defaultProtosCover(protocol) {
			return ruleOutcome{decision: fmt.Sprintf(
				"rule names no proto, which does not cover %s", protocol,
			)}
		}
	case !knownIPProtocol(entry.Protocol):
		protocolGate = fmt.Sprintf("protocol %q is not a known name or number", entry.Protocol)
	case !capabilityProtocolMatches(entry.Protocol, protocol):
		// Native tests ask whether a port-carrying protocol is allowed. A
		// recognized protocol that carries no port access therefore remains
		// a decidable non-match; whether the control plane instead asks
		// about any protocol is tracked separately from this evaluator.
		return ruleOutcome{decision: fmt.Sprintf("protocol %q did not match", entry.Protocol)}
	}
	destinations := entry.Destination
	if len(destinations) == 0 {
		destinations = entry.Ports
	}
	destinationMatched, unparseable, destinationGate := aclDestinationMatches(
		destinations, destination, matcher, source,
	)
	if !destinationMatched && !unparseable && destinationGate == "" {
		// Decidably not this rule's destination, so it is ruled out regardless
		// of anything unresolved on its source. This is the narrowing rule.
		return ruleOutcome{decision: "destination or port did not match"}
	}
	gate := firstGate(
		selectorGate("source", sourceMatched, sourceGate, source),
		selectorGate("destination", destinationMatched, destinationGate, destination.host),
		protocolGate,
		postureGate(entry.SourcePosture),
		// Legacy ACLEntry has no Via field, so there is no viaGate counterpart
		// to grantAllows here.
	)
	if gate != "" {
		// See grantAllows: a destination that could not be parsed leaves the
		// rule undecided, so it must not swallow an unresolved condition.
		return ruleOutcome{decision: "could not evaluate: " + gate, gate: gate}
	}
	if !destinationMatched {
		parseGate := "destination could not be parsed"
		return ruleOutcome{decision: "could not evaluate: " + parseGate, gate: parseGate}
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

// selectorGate renders why an unresolved selector left the verdict open, and
// what — if anything — would settle it.
//
// A role autogroup has two distinct causes and they need opposite advice, so
// they are told apart rather than sharing one sentence. Which cause applies
// follows from settlesRole: a tag settles a role autogroup outright and so
// never reaches this function, a user query is unresolved only while no roster
// was read, and a bare device address is unresolved whether or not one was.
// LooksLikeUser therefore separates them completely, and the roster hint is
// unreachable once a roster has been supplied — it cannot go stale or lie, so
// no HaveRoles parameter is needed to keep it honest.
//
// Naming a CLI flag from this package is deliberate: aclpolicy is internal to
// tail-acl, not a shared library, so the flag is always the right remedy here.
// policycore, which tailnet-audit also imports, stays free of CLI vocabulary.
func selectorGate(field string, matched bool, selector, query string) string {
	if matched || selector == "" {
		return ""
	}
	if policycore.IsRoleAutogroup(selector) {
		if policycore.LooksLikeUser(query) {
			return fmt.Sprintf(
				"%s selector %q cannot be resolved from the policy file; "+
					"supply --roster PATH to resolve role autogroups",
				field, selector,
			)
		}
		return fmt.Sprintf(
			"%s selector %q cannot be resolved for device address %q; a roster maps "+
				"logins to roles and cannot identify a device's owner",
			field, selector, query,
		)
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
	matcher policycore.Matcher,
	source string,
) (bool, string) {
	match, unresolved := matcher.AnyMatchesTri(selectors, query, source)
	return match == policycore.Matched, unresolved
}

// protocolVerdict is how one capability's protocol token relates to the query.
// The three miss kinds are distinguished because each rules the capability out
// for a different reason, and grantIPMatches records a different fact for each.
type protocolVerdict int

const (
	// protocolAdmits means the capability's protocol can answer the query, so
	// only its port range remains to be checked.
	protocolAdmits protocolVerdict = iota
	// protocolUnknown means the token is not a protocol Tailscale can parse.
	protocolUnknown
	// protocolNamedMiss means a recognized protocol that cannot answer the
	// query, so the trace can name it.
	protocolNamedMiss
	// protocolDefaultsMiss means a proto-0 spelling whose default protocol set
	// excludes the query. There is no protocol to name — the token is "*" or a
	// bare port expression — so the trace describes the set instead.
	protocolDefaultsMiss
)

// capabilityProtocolVerdict classifies a grant capability's protocol token
// against the query. The wildcard spellings answer a port question exactly like
// a bare port expression, but only for the protocols proto 0 actually expands
// to; SCTP is not among them and needs an explicit capability.
func capabilityProtocolVerdict(protocol string, query Protocol) protocolVerdict {
	switch {
	case capabilityAllProtocols(protocol):
		if !defaultProtosCover(query) {
			return protocolDefaultsMiss
		}
		return protocolAdmits
	case !knownIPProtocol(protocol):
		return protocolUnknown
	case !capabilityProtocolMatches(protocol, query):
		return protocolNamedMiss
	default:
		return protocolAdmits
	}
}

// ipMatch is grantIPMatches' answer. protocolMiss names the protocol of a
// capability whose port range did cover the query but whose protocol did not,
// so the trace can blame the field that actually decided the rule instead of
// reporting a port mismatch that never happened.
type ipMatch struct {
	matched      bool
	unparseable  bool
	protocolMiss string
	// defaultProtosMiss records a proto-0 capability whose port range did cover
	// the query but whose default protocol set does not. It is separate from
	// protocolMiss because the capability names no protocol to blame — "*" or a
	// bare port expression — so the trace has to describe the set instead.
	defaultProtosMiss bool
}

// grantIPMatches reports whether any network capability covers port, whether
// one was skipped because its port expression did not parse, and which
// protocol ruled the grant out when the port alone did not. See scanRules for
// why an unparseable element is worth distinguishing.
func grantIPMatches(capabilities []string, port uint16, query Protocol) ipMatch {
	var result ipMatch
	for _, capability := range capabilities {
		protocol, ports, found := strings.Cut(capability, ":")
		if !found {
			// A capability without a protocol is a bare port expression, which
			// carries the proto-0 protocol set. A bare "*" lands here too, as
			// the wildcard protocol over the wildcard port range.
			protocol, ports = "*", capability
		}
		hit, parsed := portSpecMatches(ports, port)
		switch capabilityProtocolVerdict(protocol, query) {
		case protocolUnknown:
			// The protocol is a defect, but the port half can still rule this
			// capability out: no protocol the author might have meant widens a
			// port range that already excludes the query. Only a port that
			// could still have matched leaves the capability unproven.
			if hit || !parsed {
				result.unparseable = true
			}
			continue
		case protocolNamedMiss:
			if hit && parsed && result.protocolMiss == "" {
				result.protocolMiss = protocol
			}
			continue
		case protocolDefaultsMiss:
			if hit && parsed {
				result.defaultProtosMiss = true
			}
			continue
		case protocolAdmits:
		}
		switch {
		case !parsed:
			result.unparseable = true
		case hit:
			return ipMatch{matched: true}
		}
	}
	return result
}

// queryProtocol reports whether protocol can satisfy a reachability question
// that does not name a protocol. This mirrors native policy tests: an omitted
// protocol asks whether any port-carrying protocol is allowed.
func queryProtocol(protocol string) bool {
	if capabilityAllProtocols(protocol) {
		return true
	}
	_, ok := networkQueryProtocol(protocol)
	return ok
}

// capabilityAllProtocols reports whether a grant capability's protocol token is
// one of the proto-0 spellings. Tailscale's ProtoPortRange parses "*" and every
// spelling of protocol 0 to the same zero value, documented as
// "TCP+UDP+ICMP(4+6)", so "0:443", "*:443", and a bare "443" are one rule
// written three ways. That set is not every port-carrying protocol — it omits
// SCTP — so callers must ask defaultProtosCover before letting one of these
// spellings answer a narrowed query. This reading belongs to grants[].ip alone:
// acls[].proto goes through ipproto.Proto, which rejects "*" and reads 0 as a
// named protocol rather than a wildcard.
func capabilityAllProtocols(token string) bool {
	if token == "*" {
		return true
	}
	number, err := strconv.ParseUint(token, 10, 8)
	return err == nil && number == 0
}

// defaultProtosCover reports whether a rule that names no protocol — a proto-0
// grant capability, or a legacy ACL entry with no proto — can answer a query
// for the given protocol.
//
// Both compile to a filter rule with no IPProto, which the packet filter
// expands to defaultProtos: TCP, UDP, ICMPv4, ICMPv6
// (tailscale.com/wgengine/filter/tailcfg.go). SCTP is port-carrying but absent
// from that set, so the wildcard grants every port question except SCTP's,
// which needs an explicit sctp: or 132: capability. The protocol-agnostic
// default is covered because TCP and UDP are.
func defaultProtosCover(query Protocol) bool {
	return query != ProtocolSCTP
}

// knownIPProtocol reports whether Tailscale can parse a protocol token as an
// ipproto.Proto. Named protocols are case-insensitive and numeric protocols
// span the full uint8 range. "*" is deliberately absent: it is a
// ProtoPortRange wildcard rather than an ipproto.Proto name, so acls[].proto
// rejects it and only capabilityAllProtocols may accept it.
func knownIPProtocol(token string) bool {
	if _, err := strconv.ParseUint(token, 10, 8); err == nil {
		return true
	}
	switch strings.ToLower(token) {
	case "ah", "dccp", "egp", "esp", "gre", "icmp", "icmpv4", "icmpv6",
		"igmp", "igp", "ip-in-ip", "ipv4", "ipv6-icmp", "sctp", "tcp", "tsmp", "udp":
		return true
	default:
		return false
	}
}

// networkQueryProtocol maps every Tailscale spelling of a port-carrying
// protocol, including case-insensitive names and numeric tokens with leading
// zeroes, onto the protocols this evaluator can ask about. TCP, UDP, and SCTP
// are the three the packet filter matches by port; every other protocol needs
// the entire port range and so answers no port question.
func networkQueryProtocol(token string) (Protocol, bool) {
	switch strings.ToLower(token) {
	case protocolTCP:
		return ProtocolTCP, true
	case protocolUDP:
		return ProtocolUDP, true
	case protocolSCTP:
		return ProtocolSCTP, true
	}
	number, err := strconv.ParseUint(token, 10, 8)
	if err != nil {
		return "", false
	}
	switch number {
	case protocolTCPNumber:
		return ProtocolTCP, true
	case protocolUDPNumber:
		return ProtocolUDP, true
	case protocolSCTPNumber:
		return ProtocolSCTP, true
	default:
		return "", false
	}
}

// capabilityProtocolMatches reports whether a rule's protocol token can satisfy
// a query for the given protocol. Both the named and numeric spellings of the
// port-carrying protocols are recognized; any other protocol answers no port
// question. The wildcard spellings never reach here — capabilityAllProtocols
// settles them for grants[].ip, and acls[].proto rejects them outright.
func capabilityProtocolMatches(token string, query Protocol) bool {
	named, ok := networkQueryProtocol(token)
	if !ok {
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
	matcher policycore.Matcher,
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
		switch matcher.MatchesTri(host, query.host, source) {
		case policycore.Matched:
			return true, false, ""
		case policycore.Unresolvable:
			if unresolved == "" {
				unresolved = host
			}
		case policycore.NoMatch:
			// Keep looking: another destination may match or be undecidable.
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
