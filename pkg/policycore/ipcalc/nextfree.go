package ipcalc

import (
	"math/big"
	"net/netip"
	"sort"
)

// NextFree returns the lowest-address targetBits child of pool that does not
// overlap a valid same-family prefix in taken. It returns false when pool or
// targetBits is invalid, or when every target-sized child overlaps an
// exclusion. Prefixes outside pool and from the other address family are
// ignored.
//
// NextFree searches the gaps between sorted, merged exclusion intervals. It
// does not materialize pool's possible children, so the search remains useful
// for large IPv4 and IPv6 pools.
func NextFree(pool netip.Prefix, targetBits int, taken []netip.Prefix) (netip.Prefix, bool) {
	if !pool.IsValid() {
		return netip.Prefix{}, false
	}

	pool = pool.Masked()
	addrBits := pool.Addr().BitLen()
	if targetBits < pool.Bits() || targetBits > addrBits {
		return netip.Prefix{}, false
	}

	blockSize := new(big.Int).Lsh(big.NewInt(1), uint(addrBits-targetBits))
	poolStart := addrToBigInt(pool.Addr())
	poolEnd := new(big.Int).Add(poolStart, new(big.Int).Lsh(big.NewInt(1), uint(addrBits-pool.Bits())))
	intervals := relevantIntervals(pool, poolStart, poolEnd, taken)

	cursor := new(big.Int).Set(poolStart)
	for _, interval := range intervals {
		if candidate, ok := alignedChild(cursor, blockSize, interval.start, poolEnd); ok {
			return netip.PrefixFrom(bigIntToAddr(candidate, pool.Addr().Is4()), targetBits), true
		}
		if interval.end.Cmp(cursor) > 0 {
			cursor.Set(interval.end)
		}
	}

	if candidate, ok := alignedChild(cursor, blockSize, poolEnd, poolEnd); ok {
		return netip.PrefixFrom(bigIntToAddr(candidate, pool.Addr().Is4()), targetBits), true
	}
	return netip.Prefix{}, false
}

type prefixInterval struct {
	start *big.Int
	end   *big.Int
}

func relevantIntervals(pool netip.Prefix, poolStart, poolEnd *big.Int, taken []netip.Prefix) []prefixInterval {
	intervals := make([]prefixInterval, 0, len(taken))
	for _, prefix := range taken {
		if !prefix.IsValid() || prefix.Addr().Is4() != pool.Addr().Is4() {
			continue
		}
		prefix = prefix.Masked()
		start := addrToBigInt(prefix.Addr())
		end := new(big.Int).Add(start, new(big.Int).Lsh(big.NewInt(1), uint(prefix.Addr().BitLen()-prefix.Bits())))
		if end.Cmp(poolStart) <= 0 || start.Cmp(poolEnd) >= 0 {
			continue
		}
		if start.Cmp(poolStart) < 0 {
			start.Set(poolStart)
		}
		if end.Cmp(poolEnd) > 0 {
			end.Set(poolEnd)
		}
		intervals = append(intervals, prefixInterval{start: start, end: end})
	}

	sort.Slice(intervals, func(i, j int) bool {
		if cmp := intervals[i].start.Cmp(intervals[j].start); cmp != 0 {
			return cmp < 0
		}
		return intervals[i].end.Cmp(intervals[j].end) < 0
	})

	return mergeIntervals(intervals)
}

func mergeIntervals(intervals []prefixInterval) []prefixInterval {
	if len(intervals) == 0 {
		return intervals
	}

	merged := make([]prefixInterval, 0, len(intervals))
	for _, interval := range intervals {
		if len(merged) == 0 || interval.start.Cmp(merged[len(merged)-1].end) > 0 {
			merged = append(merged, interval)
			continue
		}
		if interval.end.Cmp(merged[len(merged)-1].end) > 0 {
			merged[len(merged)-1].end.Set(interval.end)
		}
	}
	return merged
}

func alignedChild(cursor, blockSize, gapEnd, poolEnd *big.Int) (*big.Int, bool) {
	candidate := new(big.Int).Set(cursor)
	remainder := new(big.Int).Mod(candidate, blockSize)
	if remainder.Sign() != 0 {
		candidate.Add(candidate, new(big.Int).Sub(blockSize, remainder))
	}
	candidateEnd := new(big.Int).Add(candidate, blockSize)
	if candidateEnd.Cmp(gapEnd) <= 0 && candidateEnd.Cmp(poolEnd) <= 0 {
		return candidate, true
	}
	return nil, false
}
