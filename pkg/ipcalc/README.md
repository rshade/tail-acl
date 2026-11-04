# ipcalc

Policy-agnostic IPv4 and IPv6 subnet arithmetic: block facts, prefix splitting,
4-in-6 normalization, the next free child prefix in a pool, and aggregation of a
prefix set. It has no dependency on the rest of `tsacl`, so you can import it on
its own:

```go
import "github.com/rshade/tsacl/pkg/ipcalc"
```

`ipcalc.NextFree` returns the lowest-address child prefix of a pool at a
requested width that overlaps no same-family taken prefix, searching gaps
instead of materializing every candidate. `ipcalc.Aggregate` reduces a set of
IPv4 and IPv6 prefixes to the minimal sorted set of CIDRs covering the same
addresses, with every IPv4 result before every IPv6 result. The behavior contract is in
[`openspec/specs/ipcalc/spec.md`](../../openspec/specs/ipcalc/spec.md).

## Splitting and block facts

`ipcalc.Split` divides a parent CIDR into equal-sized child prefixes of a target
bit length. It works for both IPv4 and IPv6 and returns the children alongside
the exact child count as a `*big.Int` — since IPv6 splitting can exceed uint64
range, the count is always computed this way even when the full list cannot be
materialized. When the count would exceed `MaxMaterializedChildren` (65536),
`Split` returns `(nil, count, ErrTooManyChildren)` so the caller can report the
count without enumerating all children.

`ipcalc.Unmap4In6` rewrites an IPv4-mapped IPv6 prefix (`::ffff:a.b.c.d/n`) to
its equivalent plain IPv4 prefix. `ok` is false if the prefix is not a 4-in-6
address, or if its bit length is too short to represent a valid IPv4 prefix
once the 96-bit mapping prefix is removed. A caller that supports IPv6 can
preserve the original prefix when `ok` is false.

`ipcalc.Info` reports the classic block facts for an IPv4 prefix — network
address, broadcast address, usable host range, and usable-host count — as a
`BlockInfo`. Host bits are masked off first, so an address inside a block
yields the facts for its containing block. `Broadcast` is the zero `netip.Addr`
(`IsValid() == false`) for a `/31` (RFC 3021 point-to-point) and a `/32`
(host route), which reserve no network or broadcast address; for both, every
address in the block is usable. `UsableHosts` is a `*big.Int`, like `Split`'s
count, so an IPv6 extension cannot change the field's type. A non-IPv4 prefix
returns `ErrIPv6NotSupported` — including a 4-in-6 prefix, which callers must
normalize with `Unmap4In6` before calling.
