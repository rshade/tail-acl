package ipcalc

import (
	"errors"
	"math/big"
	"net/netip"
)

// ErrIPv6NotSupported is returned by [Info] for a prefix that is not plain
// IPv4, including an IPv4-mapped (4-in-6) prefix the caller has not run
// through [Unmap4In6]. Broadcast and usable-range subtraction are IPv4
// concepts; IPv6 block facts are deliberately unmodeled here until they
// get their own semantics.
var ErrIPv6NotSupported = errors.New("ipcalc: IPv6 prefixes are not supported")

// BlockInfo reports the classic ipcalc facts for an IPv4 block.
type BlockInfo struct {
	// Network is the block's network address (the masked prefix address).
	Network netip.Addr

	// Broadcast is the block's broadcast address. It is the zero Addr
	// (IsValid() == false) for /31 and /32, which have none: a /31 is an
	// RFC 3021 point-to-point link and a /32 is a host route.
	Broadcast netip.Addr

	// FirstUsable and LastUsable bound the usable host range. For /30 and
	// shorter they exclude the network and broadcast addresses; for /31
	// both addresses are usable (RFC 3021) and for /32 the single address
	// is the whole range.
	FirstUsable netip.Addr
	LastUsable  netip.Addr

	// UsableHosts is the number of usable host addresses. It is a
	// *big.Int, like [Split]'s count, so an IPv6 extension of this type
	// can exceed uint64 range without forking the result shape.
	UsableHosts *big.Int
}

// Info reports the network address, broadcast address, usable host range,
// and usable-host count for an IPv4 prefix. Host bits in prefix are masked
// off first, so an address inside a block yields the facts for its
// containing block. A non-IPv4 prefix returns [ErrIPv6NotSupported];
// callers accepting 4-in-6 input should normalize it with [Unmap4In6]
// before calling.
func Info(prefix netip.Prefix) (BlockInfo, error) {
	if !prefix.IsValid() {
		return BlockInfo{}, errors.New("ipcalc: invalid prefix")
	}
	if !prefix.Addr().Is4() {
		return BlockInfo{}, ErrIPv6NotSupported
	}

	prefix = prefix.Masked()
	network := prefix.Addr()

	// Block size: 2^(ipv4AddrBits - bits). The block's top address is
	// network + blockSize - 1.
	blockSize := new(big.Int).Lsh(big.NewInt(1), uint(ipv4AddrBits-prefix.Bits()))
	topInt := new(big.Int).Add(addrToBigInt(network), new(big.Int).Sub(blockSize, big.NewInt(1)))
	top := bigIntToAddr(topInt, true)

	// A /31 (RFC 3021 point-to-point) and a /32 (host route) reserve no
	// network or broadcast address, so every address in the block is a
	// usable host and UsableHosts is the whole block size.
	info := BlockInfo{Network: network}
	switch prefix.Bits() {
	case ipv4AddrBits: // /32 host route: the single address is the whole range.
		info.FirstUsable = network
		info.LastUsable = network
		info.UsableHosts = blockSize
	case ipv4AddrBits - 1: // /31 point-to-point: both addresses usable.
		info.FirstUsable = network
		info.LastUsable = top
		info.UsableHosts = blockSize
	default:
		info.Broadcast = top
		info.FirstUsable = network.Next()
		info.LastUsable = top.Prev()
		info.UsableHosts = new(big.Int).Sub(blockSize, big.NewInt(reservedNetworkAndBroadcast))
	}
	return info, nil
}

// ipv4AddrBits is the bit length of an IPv4 address. [Info] rejects
// everything but plain IPv4, so its block arithmetic uses it directly.
const ipv4AddrBits = 32

// reservedNetworkAndBroadcast is the number of addresses a classic (/30 or
// shorter) IPv4 block reserves out of its usable range: the network
// address and the broadcast address.
const reservedNetworkAndBroadcast = 2
