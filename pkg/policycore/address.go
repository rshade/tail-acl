// Package policycore resolves Tailscale policy selectors against concrete
// values. It is shared by tsacl and tailnet-audit so both tools answer
// "does this selector name this thing?" identically; two tools disagreeing
// about one policy is worse than the duplication this replaces.
//
// Scope is deliberately narrow: entity resolution only. Port, protocol, and
// via evaluation stay in tsacl; posture expression handling lives in the
// posture subpackage.
package policycore

import (
	"net/netip"
	"slices"
	"strings"

	tailscale "tailscale.com/client/tailscale/v2"
)

// v4In6PrefixBits is the length of the IPv4-mapped IPv6 prefix, subtracted to
// convert a ::ffff:0:0/96-mapped prefix back to its IPv4 length.
const v4In6PrefixBits = 96

// ExpandAddressSelector resolves a selector through Hosts and IPSets to the
// concrete addresses or prefixes it names. A Hosts value is returned as
// written: a literal address or prefix is that literal and is not looked up
// again as a host name, and any other value is returned unchanged rather than
// followed. The control plane rejects a hosts value that is not a literal, so
// following an alias chain would agree with a policy that cannot deploy. An
// IPSets entry is materialized through ResolveIPSet, so operations, ranges,
// and host: references inside it resolve, and a set that cannot be
// materialized expands to nothing. A value that names neither is returned
// unchanged, as is every value when policy is nil: a document that does not
// exist declares no aliases, so the selector already is the concrete value it
// names.
func ExpandAddressSelector(selector string, policy *tailscale.ACL) []string {
	return expandAddressSelectorSeen(selector, policy, make(map[string]bool))
}

func expandAddressSelectorSeen(selector string, policy *tailscale.ACL, seen map[string]bool) []string {
	// Guarded here rather than at the call sites because address expansion runs
	// on every selector that is not a group, so the panic this replaces reached
	// every caller of Matches.
	if policy == nil {
		return []string{selector}
	}
	if seen[selector] {
		return nil
	}
	if address, ok := policy.Hosts[selector]; ok {
		// The cycle guard stays even though a hosts value is not followed: a
		// later walk that does re-enter this selector still terminates.
		seen[selector] = true
		defer delete(seen, selector)
		return []string{address}
	}
	if _, ok := policy.IPSets[selector]; ok {
		// Expanding to nothing is the boolean caller's honest answer — no
		// address is provably covered — and selectorResolvable reports the
		// same failure as Unresolvable for the callers that can carry it.
		prefixes, err := ResolveIPSet(selector, policy)
		if err != nil {
			return nil
		}
		expanded := make([]string, 0, len(prefixes))
		for _, prefix := range prefixes {
			expanded = append(expanded, prefix.String())
		}
		return expanded
	}
	return []string{selector}
}

// hostValueLiteral reports whether value is an IP address or CIDR prefix.
// That is the only hosts value the control plane accepts.
func hostValueLiteral(value string) bool {
	if _, err := netip.ParsePrefix(value); err == nil {
		return true
	}
	_, err := netip.ParseAddr(value)
	return err == nil
}

// AddressContains reports whether selector covers query, where either may be an
// address or a prefix.
func AddressContains(selector, query string) bool {
	selectorPrefix, selectorErr := netip.ParsePrefix(selector)
	queryPrefix, queryPrefixErr := netip.ParsePrefix(query)
	if selectorErr == nil && queryPrefixErr == nil {
		return selectorPrefix.Bits() <= queryPrefix.Bits() && selectorPrefix.Contains(queryPrefix.Addr())
	}
	queryAddress, queryErr := netip.ParseAddr(strings.Trim(query, "[]"))
	if selectorErr == nil && queryErr == nil {
		return selectorPrefix.Contains(queryAddress)
	}
	selectorAddress, selectorAddressErr := netip.ParseAddr(strings.Trim(selector, "[]"))
	if selectorAddressErr == nil && queryPrefixErr == nil {
		return queryPrefix.Bits() == queryPrefix.Addr().BitLen() && queryPrefix.Contains(selectorAddress)
	}
	return selectorAddressErr == nil && queryErr == nil && selectorAddress == queryAddress
}

// IsPublicAddress reports whether value resolves to any publicly routable
// address, which is what autogroup:internet selects.
func IsPublicAddress(value string, policy *tailscale.ACL) bool {
	for _, expanded := range ExpandAddressSelector(value, policy) {
		if prefix, err := netip.ParsePrefix(expanded); err == nil {
			if publicPrefix(prefix) {
				return true
			}
			continue
		}
		address, err := netip.ParseAddr(strings.Trim(expanded, "[]"))
		if err == nil && publicAddress(address) {
			return true
		}
	}
	return false
}

func publicAddress(address netip.Addr) bool {
	return address.IsGlobalUnicast() && !address.IsPrivate() && !isTailscaleAddress(address)
}

// publicPrefix applies publicAddress to a whole range without enumerating it.
// The exclusion lists mirror netip's non-global-unicast and private ranges and
// add Tailscale's CGNAT range.
func publicPrefix(prefix netip.Prefix) bool {
	prefix = prefix.Masked()
	if prefix.Addr().Is4In6() {
		if prefix.Bits() < v4In6PrefixBits {
			return false
		}
		prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-v4In6PrefixBits)
	}

	nonPublic := nonPublicIPv6Prefixes()
	if prefix.Addr().Is4() {
		nonPublic = nonPublicIPv4Prefixes()
	}
	return !slices.ContainsFunc(nonPublic, prefix.Overlaps)
}

func nonPublicIPv4Prefixes() []netip.Prefix {
	return []netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/32"),
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("100.64.0.0/10"),
		netip.MustParsePrefix("127.0.0.0/8"),
		netip.MustParsePrefix("169.254.0.0/16"),
		netip.MustParsePrefix("172.16.0.0/12"),
		netip.MustParsePrefix("192.168.0.0/16"),
		netip.MustParsePrefix("224.0.0.0/4"),
		netip.MustParsePrefix("255.255.255.255/32"),
	}
}

func nonPublicIPv6Prefixes() []netip.Prefix {
	return []netip.Prefix{
		netip.MustParsePrefix("::/128"),
		netip.MustParsePrefix("::1/128"),
		netip.MustParsePrefix("fc00::/7"),
		netip.MustParsePrefix("fe80::/10"),
		netip.MustParsePrefix("ff00::/8"),
	}
}

func isTailscaleAddress(address netip.Addr) bool {
	return netip.MustParsePrefix("100.64.0.0/10").Contains(address) ||
		netip.MustParsePrefix("fd7a:115c:a1e0::/48").Contains(address)
}
