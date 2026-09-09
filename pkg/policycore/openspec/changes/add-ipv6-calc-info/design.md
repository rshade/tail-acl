# Design: add-ipv6-calc-info

## Context

See proposal.md. `Info` already masks IPv4 prefixes and derives a top address
with big-integer arithmetic, while `Split` proves the package's helpers work
for both address families. The existing result type intentionally uses
`*big.Int` to allow this extension.

## Goals / Non-Goals

**Goals:**

- Preserve all IPv4 results and add correct IPv6 facts through the same API.
- Keep absent broadcast represented by an invalid `netip.Addr`, which the CLI
  already maps to an omitted field.

**Non-Goals:**

- Adding IPv6-specific concepts beyond the requested block facts.
- Changing the 4-in-6 normalization contract, which remains a caller concern.

## Decisions

### Use one family-aware `Info` implementation

Mask the prefix, calculate the address-space size as `2^(bitWidth-prefix)` and
derive the top address with the existing conversion helpers. IPv4 retains its
reserved-address rules; IPv6 returns the masked network and top address as the
usable range. This avoids duplicated APIs while retaining each family's
semantics.

### Keep exact decimal-capable counts without a presentation cutoff

`*big.Int` holds the full IPv6 count. The maximum count, `2^128`, has 39
decimal digits, so callers can safely render it exactly rather than switching
to `2^k` notation. Exact decimal is unambiguous and needs no consumer-side
special parsing.

### Deprecate but retain the IPv6 sentinel

`Info` no longer returns `ErrIPv6NotSupported`, but the exported symbol remains
deprecated for source compatibility with existing callers. The function
continues to reject only invalid prefixes with an ordinary error.

## Risks / Trade-offs

- [Incorrect top-address conversion crosses an address-family boundary] →
  cover `/48`, `/64`, `/127`, `/128`, host-bit masking, and exact counts.
- [Existing IPv4 edge behavior regresses] → retain existing IPv4 test cases
  unchanged and execute the full module suite.
