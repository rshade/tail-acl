package aclpolicy

import (
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strings"

	tailscale "tailscale.com/client/tailscale/v2"

	"github.com/rshade/tsacl/pkg/policycore"
)

func lintIPSetMembers(policy *tailscale.ACL) []LintFinding {
	if policy == nil {
		return nil
	}
	var findings []LintFinding
	seenCycles := map[string]struct{}{}
	for _, name := range slices.Sorted(maps.Keys(policy.IPSets)) {
		findings = append(findings, lintOneIPSet(policy, name, seenCycles)...)
	}
	return findings
}

func lintOneIPSet(policy *tailscale.ACL, name string, seenCycles map[string]struct{}) []LintFinding {
	var findings []LintFinding
	for index, raw := range policy.IPSets[name] {
		member, err := policycore.ParseIPSetMember(raw)
		if err != nil {
			findings = append(findings, ipsetMemberFinding(name, index, raw, err))
			continue
		}
		if finding, ok := ipsetReferenceFinding(policy, name, index, raw, member, seenCycles); ok {
			findings = append(findings, finding)
		}
	}
	return findings
}

func ipsetMemberFinding(name string, index int, raw string, err error) LintFinding {
	locator := fmt.Sprintf("ipsets[%s][%d]", name, index)
	return LintFinding{
		ID:          LintIPSetMemberInvalid,
		Severity:    LintError,
		Rule:        locator,
		Value:       raw,
		Evidence:    fmt.Sprintf("ipset %s member %q: %s", name, raw, err),
		Remediation: "rewrite the member as an address, CIDR, range, host: alias, or ipset: reference",
		Trace: []string{
			locator,
			err.Error(),
		},
	}
}

func ipsetReferenceFinding(
	policy *tailscale.ACL,
	name string,
	index int,
	raw string,
	member policycore.IPSetMember,
	seenCycles map[string]struct{},
) (LintFinding, bool) {
	locator := fmt.Sprintf("ipsets[%s][%d]", name, index)
	if alias, ok := member.HostAlias(); ok {
		if _, defined := policy.Hosts[alias]; defined {
			return LintFinding{}, false
		}
		return undefinedIPSetReference(locator, name, raw, "host alias "+alias, "hosts"), true
	}
	if member.Kind != policycore.IPSetMemberIPSet {
		return LintFinding{}, false
	}
	if _, defined := policy.IPSets[member.Target]; !defined {
		return undefinedIPSetReference(locator, name, raw, member.Target, "ipsets"), true
	}
	path := ipsetReferencePath(policy.IPSets, member.Target, name, map[string]bool{})
	if path == nil {
		return LintFinding{}, false
	}
	full := append([]string{name}, path...)
	if name != slices.Min(full) {
		return LintFinding{}, false
	}
	rendered := strings.Join(full, " -> ")
	if _, seen := seenCycles[rendered]; seen {
		return LintFinding{}, false
	}
	seenCycles[rendered] = struct{}{}
	evidence := fmt.Sprintf("ipset %s member %q creates a cycle: %s", name, raw, rendered)
	return LintFinding{
		ID:          LintIPSetReferenceCycle,
		Severity:    LintError,
		Rule:        locator,
		Value:       raw,
		Evidence:    evidence,
		Remediation: "break the cycle so each ipset reference reaches a set that does not refer back",
		Trace:       []string{locator, evidence},
	}, true
}

func undefinedIPSetReference(locator, name, raw, target, container string) LintFinding {
	evidence := fmt.Sprintf(
		"ipset %s member %q references %s, which is not defined in %s",
		name, raw, target, container,
	)
	return LintFinding{
		ID:          LintIPSetReferenceUndefined,
		Severity:    LintError,
		Rule:        locator,
		Value:       raw,
		Evidence:    evidence,
		Remediation: "define " + target + ", or remove the member",
		Trace:       []string{locator, evidence},
	}
}

func lintHostAddresses(policy *tailscale.ACL) []LintFinding {
	if policy == nil {
		return nil
	}
	var findings []LintFinding
	for _, name := range slices.Sorted(maps.Keys(policy.Hosts)) {
		value := policy.Hosts[name]
		if hostValueIsAddress(value) {
			continue
		}
		findings = append(findings, hostNotAddress(policy, name, value))
	}
	return findings
}

func hostValueIsAddress(value string) bool {
	if _, err := netip.ParsePrefix(value); err == nil {
		return true
	}
	_, err := netip.ParseAddr(value)
	return err == nil
}

func hostNotAddress(policy *tailscale.ACL, name, value string) LintFinding {
	locators := []string{fmt.Sprintf("hosts[%s]", name)}
	var references []string
	for _, set := range slices.Sorted(maps.Keys(policy.IPSets)) {
		for index, raw := range policy.IPSets[set] {
			member, err := policycore.ParseIPSetMember(raw)
			if err != nil {
				continue
			}
			alias, ok := member.HostAlias()
			if ok && alias == name {
				locators = append(locators, fmt.Sprintf("ipsets[%s][%d]", set, index))
				references = append(references, fmt.Sprintf("ipset %s member %q", set, raw))
			}
		}
	}
	evidence := fmt.Sprintf("host %s value %q is not an address or prefix", name, value)
	if len(references) != 0 {
		evidence += "; " + strings.Join(references, ", ")
	}
	return LintFinding{
		ID:          LintHostNotAddress,
		Severity:    LintError,
		Rule:        strings.Join(locators, ", "),
		Value:       value,
		Evidence:    evidence,
		Remediation: "set the host to an IP address or a CIDR prefix",
		Trace:       append(slices.Clone(locators), evidence),
	}
}
