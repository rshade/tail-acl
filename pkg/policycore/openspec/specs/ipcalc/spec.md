# Ipcalc Specification

## Purpose

Provide policy-agnostic IPv4/IPv6 subnet arithmetic — classic block facts,
prefix splitting, and 4-in-6 normalization — with no knowledge of
`tail-ipam`'s registry, CLI, or Tailscale-specific concepts.

## Requirements

### Requirement: IPv4 block facts account for the /31 and /32 special cases

The ipcalc capability SHALL report an IPv4 prefix's network address,
broadcast address, usable host range, and usable-host count, masking host
bits off first. For a `/30` or shorter, the network and broadcast addresses
SHALL be excluded from the usable range. For a `/31` (RFC 3021
point-to-point) neither address SHALL be reserved and both SHALL be usable;
for a `/32` the single address SHALL be both the network and the whole usable
range, and neither case SHALL report a broadcast address.

#### Scenario: A /31 point-to-point link has no broadcast and two usable hosts

- **WHEN** `Info` is called on `10.0.0.0/31`
- **THEN** it reports no broadcast address, `FirstUsable=10.0.0.0`,
  `LastUsable=10.0.0.1`, and `UsableHosts=2`

#### Scenario: A non-IPv4 or invalid prefix is rejected

- **WHEN** `Info` is given a native IPv6 prefix, an unmapped 4-in-6 prefix, or
  an invalid `netip.Prefix`
- **THEN** it returns `ErrIPv6NotSupported` for the first two cases and a
  distinct plain error for the invalid prefix

### Requirement: Splitting a prefix validates target width and caps materialization

The ipcalc capability SHALL divide a parent prefix into equal-sized child
prefixes of a target bit length, working for both IPv4 and IPv6, and SHALL
reject a target shorter than the parent or longer than the address family's
bit length. When the exact child count exceeds 65536
(`MaxMaterializedChildren`), it SHALL return that exact count as a
`*big.Int` alongside `ErrTooManyChildren` and no materialized children,
rather than silently truncating.

#### Scenario: An oversized split reports the exact count without children

- **WHEN** `Split` divides `10.0.0.0/8` into `/32`s (16,777,216 children)
- **THEN** it returns `nil` children, a count of `16777216`, and
  `ErrTooManyChildren`

#### Scenario: A target narrower than the parent is rejected

- **WHEN** `Split` is given a parent `/24` and a target of `/16`
- **THEN** it returns an error naming the target as shorter than the parent

### Requirement: 4-in-6 prefixes normalize to plain IPv4

The ipcalc capability SHALL rewrite an IPv4-mapped IPv6 prefix
(`::ffff:a.b.c.d/n`) to its equivalent plain IPv4 prefix when the prefix is
at least 96 bits wide, and SHALL report failure for a plain IPv6 prefix, a
plain IPv4 prefix, or a mapped prefix narrower than 96 bits.

#### Scenario: A fully-mapped /120 unmaps to a /24

- **WHEN** `Unmap4In6` is given `::ffff:10.0.0.0/120`
- **THEN** it returns `10.0.0.0/24` and `ok=true`
