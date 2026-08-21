// Package addrspace compares Tailscale route CIDRs for address overlap. It
// knows nothing about ACL policy text, live device inventories, or 4via6
// site-ID derivation — tail-acl and tailnet-audit each supply their own CIDR
// strings, static or live, and interpret the results themselves.
package addrspace

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

// v4In6PrefixBits is the length of the IPv4-mapped IPv6 prefix, subtracted to
// convert a ::ffff:0:0/96-mapped prefix back to its IPv4 length so it
// compares correctly against a plain IPv4 prefix. Mirrors the constant of the
// same name in the parent policycore package.
const v4In6PrefixBits = 96

// Overlaps reports whether a and b share any address. Each argument may be a
// CIDR prefix or a bare address (optionally bracketed, as Tailscale IPv6
// addresses sometimes are). It returns an error if either argument fails to
// parse as either form.
func Overlaps(a, b string) (bool, error) {
	prefixA, err := parseAddressOrPrefix(a)
	if err != nil {
		return false, fmt.Errorf("addrspace: %q: %w", a, err)
	}
	prefixB, err := parseAddressOrPrefix(b)
	if err != nil {
		return false, fmt.Errorf("addrspace: %q: %w", b, err)
	}
	return prefixesOverlap(prefixA, prefixB), nil
}

// OverlappingPairs returns the index pairs (i, j), i < j, of cidrs entries
// that overlap, and any per-entry parse errors keyed by index. A malformed
// entry is reported in the returned error map and excluded from every
// pairwise comparison rather than aborting the whole call, so one bad entry
// in a larger set never hides the overlaps among the rest. A nil error map
// means every entry parsed.
func OverlappingPairs(cidrs []string) ([][2]int, map[int]error) {
	prefixes := make([]netip.Prefix, len(cidrs))
	parsed := make([]bool, len(cidrs))
	var errs map[int]error
	for index, cidr := range cidrs {
		prefix, err := parseAddressOrPrefix(cidr)
		if err != nil {
			if errs == nil {
				errs = make(map[int]error)
			}
			errs[index] = fmt.Errorf("addrspace: %q: %w", cidr, err)
			continue
		}
		prefixes[index] = prefix
		parsed[index] = true
	}

	var pairs [][2]int
	for i := range cidrs {
		if !parsed[i] {
			continue
		}
		for j := i + 1; j < len(cidrs); j++ {
			if parsed[j] && prefixesOverlap(prefixes[i], prefixes[j]) {
				pairs = append(pairs, [2]int{i, j})
			}
		}
	}
	return pairs, errs
}

// parseAddressOrPrefix parses value as a CIDR prefix, falling back to a bare
// address (a full-length host prefix). It retains the original address family
// so IPv4-mapped IPv6 prefixes can still overlap enclosing IPv6 prefixes.
func parseAddressOrPrefix(value string) (netip.Prefix, error) {
	if prefix, err := netip.ParsePrefix(value); err == nil {
		return prefix.Masked(), nil
	}

	address := value
	if strings.HasPrefix(value, "[") && strings.HasSuffix(value, "]") {
		address = value[1 : len(value)-1]
		if strings.ContainsAny(address, "[]") {
			return netip.Prefix{}, errors.New("not a valid address or CIDR: malformed brackets")
		}
	} else if strings.ContainsAny(value, "[]") {
		return netip.Prefix{}, errors.New("not a valid address or CIDR: malformed brackets")
	}

	addr, err := netip.ParseAddr(address)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("not a valid address or CIDR: %w", err)
	}
	return netip.PrefixFrom(addr, addr.BitLen()), nil
}

// prefixesOverlap compares prefixes in their original address families first
// to preserve IPv6 containment, then compares their normalized forms so a
// fully IPv4-mapped IPv6 prefix also overlaps its plain IPv4 representation.
func prefixesOverlap(a, b netip.Prefix) bool {
	if a.Overlaps(b) {
		return true
	}
	return normalizePrefix(a).Overlaps(normalizePrefix(b))
}

// normalizePrefix masks prefix to its canonical form and unmaps a fully
// IPv4-mapped IPv6 prefix (bits >= v4In6PrefixBits) back to plain IPv4. A
// narrower IPv4-mapped-family prefix spans more of the IPv6 address space
// than the mapped range alone, so it is left as IPv6 and compares against a
// plain IPv4 prefix as a family mismatch rather than a false overlap.
func normalizePrefix(prefix netip.Prefix) netip.Prefix {
	prefix = prefix.Masked()
	if prefix.Addr().Is4In6() && prefix.Bits() >= v4In6PrefixBits {
		return netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-v4In6PrefixBits)
	}
	return prefix
}
