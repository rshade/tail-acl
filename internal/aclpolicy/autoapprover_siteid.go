package aclpolicy

import (
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	tailscale "tailscale.com/client/tailscale/v2"
	"tailscale.com/net/tsaddr"

	"github.com/rshade/tsacl/pkg/policycore/addrspace"
)

// minDistinctViaSubnets is the count that makes one site ID cover more
// than one IPv4 prefix.
const minDistinctViaSubnets = 2

func lintAutoApproverSiteIDCollision(policy *tailscale.ACL) []LintFinding {
	if policy == nil || policy.AutoApprovers == nil {
		return nil
	}
	grouped := map[uint32][]string{}
	subnets := map[uint32]map[string]struct{}{}
	for _, key := range slices.Sorted(maps.Keys(policy.AutoApprovers.Routes)) {
		site, subnet, ok := viaSiteSubnet(key)
		if !ok {
			continue
		}
		grouped[site] = append(grouped[site], key)
		if subnets[site] == nil {
			subnets[site] = map[string]struct{}{}
		}
		subnets[site][subnet] = struct{}{}
	}
	var findings []LintFinding
	for _, site := range slices.Sorted(maps.Keys(grouped)) {
		if len(subnets[site]) < minDistinctViaSubnets {
			continue
		}
		findings = append(findings, siteIDAdvice(site, grouped[site]))
	}
	return findings
}

func viaSiteSubnet(route string) (uint32, string, bool) {
	if !addrspace.IsViaPrefix(route) {
		return 0, "", false
	}
	site, ok := addrspace.SiteID(route)
	if !ok {
		return 0, "", false
	}
	prefix, err := netip.ParsePrefix(route)
	if err != nil {
		return 0, "", false
	}
	address := tsaddr.UnmapVia(prefix.Addr())
	if !address.Is4() {
		return 0, "", false
	}
	// MapVia adds the via-range length and the IPv4 address length.
	bits := prefix.Bits() - (tsaddr.TailscaleViaRange().Bits() + address.BitLen())
	if bits < 0 || bits > address.BitLen() {
		return 0, "", false
	}
	return site, netip.PrefixFrom(address, bits).Masked().String(), true
}

func siteIDAdvice(site uint32, keys []string) LintFinding {
	locators := make([]string, len(keys))
	for index, key := range keys {
		locators[index] = fmt.Sprintf("autoApprovers.routes[%s]", key)
	}
	id := strconv.FormatUint(uint64(site), 10)
	evidence := fmt.Sprintf(
		"autoApprovers.routes entries share site ID %s; confirm they are the same site", id,
	)
	return LintFinding{
		ID:          LintAutoApproverSiteIDCollision,
		Severity:    LintAdvice,
		Rule:        strings.Join(locators, ", "),
		Value:       id,
		Evidence:    evidence,
		Remediation: "confirm these routes are the same site, or give a different site its own site ID",
		Trace:       append(slices.Clone(locators), evidence),
	}
}
