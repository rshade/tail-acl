package aclpolicy

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	tailscale "tailscale.com/client/tailscale/v2"

	"github.com/rshade/tail-acl/pkg/policycore"
)

const (
	minimumPolicyPort = 1
	maximumPolicyPort = 65535

	// autogroupDangerAll names every device, including devices outside the
	// tailnet — policycore resolves it with matchesAlways, documenting it as
	// restoring the pre-mitigation meaning of "*". It is therefore strictly
	// broader than "*" and is spelled once here so the breadth predicate and the
	// overbroad-wildcard check cannot drift apart on it.
	autogroupDangerAll = "autogroup:danger-all"
)

// lintBroadRuleUntested joins the breadth predicate to deny-test coverage. It
// deliberately examines grants only; legacy ACL entries are a v2 concern.
func lintBroadRuleUntested(policy *tailscale.ACL, allowBroad []string) []LintFinding {
	covered := denyCoveredDestinations(policy.Tests)
	excluded := normalizedSet(allowBroad)
	findings := make([]LintFinding, 0)
	for grantIndex, grant := range policy.Grants {
		blanketSource := preferredBlanketSelector(grant.Source)
		if blanketSource == "" || len(grant.SrcPosture) != 0 || len(grant.Via) != 0 || !opensEveryPort(grant.IP) {
			continue
		}
		for destinationIndex, rawDestination := range grant.Destination {
			destination := strings.TrimSpace(rawDestination)
			if !isConcreteBroadDestination(destination) || covered[destination] || excluded[destination] {
				continue
			}
			locator := fmt.Sprintf("grants[%d].dst[%d]", grantIndex, destinationIndex)
			finding := LintFinding{
				ID:          LintBroadRuleUntested,
				Severity:    LintAdvice,
				Rule:        locator,
				Value:       destination,
				Evidence:    "broad grant reaches " + destination + " on every port and no deny assertion names it",
				Remediation: "add a deny assertion for " + destination + ", then narrow the grant until the assertion passes",
				Trace: []string{
					fmt.Sprintf("grants[%d] source contains blanket selector %s", grantIndex, blanketSource),
					fmt.Sprintf("grants[%d] network capability opens every port", grantIndex),
					destination + " is a concrete destination",
					"no tests[].deny entry names " + destination,
				},
			}
			finding.Suggestion, finding.Trace = broadRuleSuggestion(
				policy, grantIndex, blanketSource, destination, finding.Trace,
			)
			findings = append(findings, finding)
		}
	}
	return findings
}

// isBlanketSelector reports whether a selector is broad enough that a grant
// using it as a source is worth advising on. autogroup:danger-all belongs here
// because policycore resolves it with matchesAlways — it names every device,
// including devices outside the tailnet, so it is strictly broader than "*".
func isBlanketSelector(selector string) bool {
	switch strings.TrimSpace(selector) {
	case "*", autogroupDangerAll, "autogroup:member", "autogroup:members", "autogroup:tagged":
		return true
	default:
		return false
	}
}

// preferredBlanketSelector chooses a deterministic, testable blanket identity
// when one is available. A bare wildcard still establishes breadth, but it is
// the fallback because Tailscale policy tests cannot use it as a source.
func preferredBlanketSelector(selectors []string) string {
	blanket := make([]string, 0, len(selectors))
	for _, selector := range selectors {
		if selector = strings.TrimSpace(selector); isBlanketSelector(selector) {
			blanket = append(blanket, selector)
		}
	}
	if len(blanket) == 0 {
		return ""
	}
	sort.Strings(blanket)
	for _, selector := range blanket {
		if selector != "*" {
			return selector
		}
	}
	return blanket[0]
}

// isConcreteBroadDestination reports whether a destination is specific enough to
// write a targeted deny assertion against. No autogroup qualifies: each one
// names a set whose membership is either self-limiting (autogroup:self),
// address-derived (autogroup:internet), unrestricted (autogroup:danger-all), or
// answerable only from live control-plane state (the role autogroups, which
// tailnet-audit's grant-dst-widespread owns). Excluding the prefix rather than
// naming members also means an autogroup Tailscale ships later cannot
// false-positive here as a "concrete" destination.
func isConcreteBroadDestination(destination string) bool {
	if destination == "" || strings.HasPrefix(destination, "autogroup:") {
		return false
	}
	return !isBlanketSelector(destination)
}

// opensEveryPort reports whether any capability spans the whole port range.
// It samples both endpoints through the package's real port-spec parser rather
// than matching the spec text, so equivalent spellings the control plane
// accepts — "0-65535", or a split range like "tcp:1-1000,1001-65535" — are not
// silently missed. Sampling two endpoints is not a proof of full coverage, but
// a false negative here means an all-port grant this advisory exists to find
// passes unreported, which is the expensive direction to be wrong in.
func opensEveryPort(capabilities []string) bool {
	for _, capability := range capabilities {
		_, ports, found := strings.Cut(strings.TrimSpace(capability), ":")
		if !found {
			ports = capability
		}
		ports = strings.TrimSpace(ports)
		if ports == "*" {
			return true
		}
		lowMatched, lowParsed := portSpecMatches(ports, minimumPolicyPort)
		highMatched, highParsed := portSpecMatches(ports, maximumPolicyPort)
		if lowParsed && highParsed && lowMatched && highMatched {
			return true
		}
	}
	return false
}

func normalizedSet(values []string) map[string]bool {
	set := make(map[string]bool, len(values))
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			set[value] = true
		}
	}
	return set
}

func denyCoveredDestinations(tests []tailscale.ACLTest) map[string]bool {
	covered := make(map[string]bool)
	for _, test := range tests {
		for _, deny := range test.Deny {
			// splitSelectorPort rather than destinationHost: the latter is
			// documented to reject portless input, and a portless deny would
			// otherwise truncate to a garbage host ("tag:db" -> "tag"). A
			// portless deny is not a readable assertion — tail-acl test reports
			// it — so it contributes no coverage instead of a truncated key.
			host, _, ok := splitSelectorPort(strings.TrimSpace(deny))
			if !ok {
				continue
			}
			if host = strings.TrimSpace(host); host != "" {
				covered[host] = true
			}
		}
	}
	return covered
}

func broadRuleSuggestion(
	policy *tailscale.ACL,
	triggeringGrant int,
	source string,
	destination string,
	trace []string,
) (string, []string) {
	if source == "*" {
		return "", append(trace, "suggestion omitted: * is not a testable source identity")
	}
	testSource, ok := derivedTestSource(policy, source, destination)
	if !ok {
		return "", append(trace, "suggestion omitted: no concrete test source can be derived for "+source)
	}
	port, ok := lowestAssociatedPort(policy, triggeringGrant, destination)
	if !ok {
		return "", append(trace, "suggestion omitted: no concrete port is associated with "+destination)
	}
	test := tailscale.ACLTest{Source: testSource, Deny: []string{formatTestDestination(destination, port)}}
	// Marshal the schema type first, then project it only to pin the paste-ready
	// key order (src before deny) independently of the dependency's field order.
	encoded, err := json.Marshal(test)
	if err != nil {
		return "", append(trace, "suggestion omitted: could not encode derived ACL test")
	}
	var paste struct {
		Source string   `json:"src"`
		Deny   []string `json:"deny"`
	}
	if err = json.Unmarshal(encoded, &paste); err != nil {
		return "", append(trace, "suggestion omitted: could not encode derived ACL test")
	}
	// Verify the projection actually found the fields. If the pinned client ever
	// renames ACLTest's json tags, this reports an omission rather than emitting
	// a well-formed suggestion with an empty src that the control plane rejects.
	if paste.Source != testSource || len(paste.Deny) != 1 {
		return "", append(trace, "suggestion omitted: could not encode derived ACL test")
	}
	encoded, err = json.Marshal(paste)
	if err != nil {
		return "", append(trace, "suggestion omitted: could not encode derived ACL test")
	}
	trace = append(trace, fmt.Sprintf("suggestion derives test source %s from %s", testSource, source))
	return string(encoded), append(trace, fmt.Sprintf("suggestion uses derived port %d for %s", port, destination))
}

// derivedTestSource projects a broad selector onto one specific identity the
// control-plane tests schema accepts. Policy tests require a user, group, tag,
// or host source rather than an autogroup, so the advisory must not paste the
// blanket selector itself into tests[].src.
//
// destination is excluded from the candidate set: a deny assertion whose source
// equals its destination asserts that a selector cannot reach itself, which
// intra-tag traffic (database peers, replication) legitimately contradicts. The
// suggestion is omitted rather than made self-referential.
func derivedTestSource(policy *tailscale.ACL, blanket, destination string) (string, bool) {
	var candidates []string
	switch blanket {
	case "autogroup:member", "autogroup:members":
		for _, members := range policy.Groups {
			for _, member := range members {
				member = strings.TrimSpace(member)
				if policycore.LooksLikeUser(member) {
					candidates = append(candidates, member)
				}
			}
		}
	case "autogroup:tagged":
		for tag := range policy.TagOwners {
			tag = strings.TrimSpace(tag)
			if strings.HasPrefix(tag, "tag:") {
				candidates = append(candidates, tag)
			}
		}
	}
	if len(candidates) == 0 {
		return "", false
	}
	sort.Strings(candidates)
	for _, candidate := range candidates {
		if candidate != destination {
			return candidate, true
		}
	}
	return "", false
}

func formatTestDestination(destination string, port uint16) string {
	if address, err := netip.ParseAddr(destination); err == nil && address.Is6() {
		return fmt.Sprintf("[%s]:%d", destination, port)
	}
	return fmt.Sprintf("%s:%d", destination, port)
}

func lowestAssociatedPort(policy *tailscale.ACL, triggeringGrant int, destination string) (uint16, bool) {
	lowest := maximumPolicyPort + 1
	for _, spec := range associatedPortSpecs(policy, triggeringGrant, destination) {
		if port, ok := lowestConcretePort(spec); ok && int(port) < lowest {
			lowest = int(port)
		}
	}
	if lowest > maximumPolicyPort {
		return 0, false
	}
	return uint16(lowest), true
}

func associatedPortSpecs(policy *tailscale.ACL, triggeringGrant int, destination string) []string {
	var specs []string
	specs = append(specs, grantPortSpecs(policy.Grants, triggeringGrant, destination)...)
	specs = append(specs, aclPortSpecs(policy.ACLs, destination)...)
	return append(specs, testPortSpecs(policy.Tests, destination)...)
}

func grantPortSpecs(grants []tailscale.Grant, triggeringGrant int, destination string) []string {
	var specs []string
	for index, grant := range grants {
		if index == triggeringGrant || !containsTrimmed(grant.Destination, destination) {
			continue
		}
		for _, capability := range grant.IP {
			_, ports, found := strings.Cut(strings.TrimSpace(capability), ":")
			if !found {
				ports = capability
			}
			specs = append(specs, strings.TrimSpace(ports))
		}
	}
	return specs
}

func aclPortSpecs(entries []tailscale.ACLEntry, destination string) []string {
	var specs []string
	for _, entry := range entries {
		for _, target := range aclDestinations(entry) {
			host, ports, ok := splitSelectorPort(strings.TrimSpace(target))
			if ok && strings.TrimSpace(host) == destination {
				specs = append(specs, ports)
			}
		}
	}
	return specs
}

func testPortSpecs(tests []tailscale.ACLTest, destination string) []string {
	var specs []string
	for _, test := range tests {
		destinations := append(append(append([]string{}, test.Accept...), test.Allow...), test.Deny...)
		for _, target := range destinations {
			host, ports, ok := splitSelectorPort(strings.TrimSpace(target))
			if ok && strings.TrimSpace(host) == destination {
				specs = append(specs, ports)
			}
		}
	}
	return specs
}

func containsTrimmed(values []string, target string) bool {
	for _, value := range values {
		if strings.TrimSpace(value) == target {
			return true
		}
	}
	return false
}

func lowestConcretePort(spec string) (uint16, bool) {
	lowest := maximumPolicyPort + 1
	for part := range strings.SplitSeq(strings.TrimSpace(spec), ",") {
		startText, endText, hasRange := strings.Cut(strings.TrimSpace(part), "-")
		start, err := strconv.Atoi(startText)
		if err != nil || start < minimumPolicyPort || start > maximumPolicyPort {
			continue
		}
		if hasRange {
			end, endErr := strconv.Atoi(endText)
			if endErr != nil || end < start || end > maximumPolicyPort {
				continue
			}
		}
		if start < lowest {
			lowest = start
		}
	}
	if lowest > maximumPolicyPort {
		return 0, false
	}
	return uint16(lowest), true
}
