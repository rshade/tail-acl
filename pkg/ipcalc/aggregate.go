package ipcalc

import (
	"net/netip"
	"sort"
)

// Aggregate returns the minimal CIDR cover of prefixes. It masks prefixes,
// drops prefixes already covered by a wider prefix, and repeatedly replaces
// adjacent sibling prefixes with their parent. The result is ordered by
// network address. Both address families may be supplied together: a prefix
// never merges with or is covered by a prefix of the other family, and every
// IPv4 result precedes every IPv6 result. Callers must provide valid prefixes.
func Aggregate(prefixes []netip.Prefix) []netip.Prefix {
	if len(prefixes) == 0 {
		return nil
	}

	sorted := make([]netip.Prefix, len(prefixes))
	for i, prefix := range prefixes {
		sorted[i] = prefix.Masked()
	}
	sort.Slice(sorted, func(i, j int) bool {
		if cmp := sorted[i].Addr().Compare(sorted[j].Addr()); cmp != 0 {
			return cmp < 0
		}
		return sorted[i].Bits() < sorted[j].Bits()
	})

	result := make([]netip.Prefix, 0, len(sorted))
	for _, prefix := range sorted {
		if len(result) > 0 && result[len(result)-1].Contains(prefix.Addr()) {
			continue
		}

		result = append(result, prefix)
		for len(result) >= 2 {
			left := result[len(result)-2]
			right := result[len(result)-1]
			if !siblings(left, right) {
				break
			}
			result = result[:len(result)-2]
			result = append(result, netip.PrefixFrom(left.Addr(), left.Bits()-1).Masked())
		}
	}
	return result
}

func siblings(left, right netip.Prefix) bool {
	if left.Addr().Is4() != right.Addr().Is4() || left.Bits() != right.Bits() || left.Bits() == 0 {
		return false
	}
	parent := netip.PrefixFrom(left.Addr(), left.Bits()-1).Masked()
	return parent.Contains(right.Addr())
}
