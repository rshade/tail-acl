package aclpolicy

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	tailscale "tailscale.com/client/tailscale/v2"
)

const (
	minimumPolicyPort = 1
	maximumPolicyPort = 65535
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

func isBlanketSelector(selector string) bool {
	switch strings.TrimSpace(selector) {
	case "*", "autogroup:member", "autogroup:members", "autogroup:tagged":
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

func isConcreteBroadDestination(destination string) bool {
	switch destination {
	case "", "autogroup:internet", "autogroup:self":
		return false
	default:
		return !isBlanketSelector(destination)
	}
}

func opensEveryPort(capabilities []string) bool {
	for _, capability := range capabilities {
		_, ports, found := strings.Cut(strings.TrimSpace(capability), ":")
		if !found {
			ports = capability
		}
		ports = strings.TrimSpace(ports)
		if ports == "*" || ports == "1-65535" {
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
			if host := strings.TrimSpace(destinationHost(strings.TrimSpace(deny))); host != "" {
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
	port, ok := lowestAssociatedPort(policy, triggeringGrant, destination)
	if !ok {
		return "", append(trace, "suggestion omitted: no concrete port is associated with "+destination)
	}
	test := tailscale.ACLTest{Source: source, Deny: []string{formatTestDestination(destination, port)}}
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
	encoded, err = json.Marshal(paste)
	if err != nil {
		return "", append(trace, "suggestion omitted: could not encode derived ACL test")
	}
	return string(encoded), append(trace, fmt.Sprintf("suggestion uses derived port %d for %s", port, destination))
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
