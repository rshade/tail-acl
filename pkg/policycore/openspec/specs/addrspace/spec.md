# Addrspace Specification

## Purpose

Provide policy-agnostic address-space primitives — CIDR/address overlap
comparison and 4via6 "via" prefix decoding — with no knowledge of ACL policy
text or live device inventories, for `tsacl` and `tailnet-audit` to build
their own overlap and site-ID checks on.

## Requirements

### Requirement: Pairwise overlap detection across addresses and prefixes

The addrspace capability SHALL report whether two values, each either a CIDR
prefix or a bare (optionally bracketed) address, share any address, including
across an IPv4-mapped IPv6 prefix and its plain IPv4 equivalent. A value that
parses as neither form SHALL be rejected with an error naming which argument
failed.

#### Scenario: Mapped IPv6 prefix overlaps its plain IPv4 equivalent

- **WHEN** `Overlaps("::ffff:10.0.0.0/104", "10.0.0.0/16")` is called
- **THEN** it returns `true`, because the mapped prefix's IPv4 range and the
  plain IPv4 prefix overlap

#### Scenario: Malformed bracket syntax is rejected

- **WHEN** `Overlaps` is given `"[fd7a:115c:a1e0::1"` (a missing closing
  bracket)
- **THEN** it returns an error rather than a boolean

### Requirement: Batch overlap detection isolates malformed entries

Given a list of address/prefix strings, the addrspace capability SHALL
return every overlapping index pair `(i, j)`, `i < j`, sorted ascending, plus
a per-index error map for entries that fail to parse. A malformed entry
SHALL be excluded from every pairwise comparison rather than aborting the
whole call, so it never hides overlaps among the remaining entries.

#### Scenario: One malformed entry does not hide overlaps among the rest

- **WHEN** `OverlappingPairs` is given `["10.0.0.0/8", "garbage",
  "10.1.0.0/16", "11.0.0.0/8"]`
- **THEN** it reports the pair `(0, 2)`, an error keyed at index `1`, and no
  other pairs

### Requirement: 4via6 site-ID extraction validates range, width, and value

The addrspace capability SHALL extract the 16-bit site ID embedded in a
Tailscale 4via6 "via" IPv6 CIDR only when the CIDR lies within the via range,
carries a prefix length of at least `/96`, and encodes a site ID no greater
than 65535; any other input SHALL report failure rather than a value.

#### Scenario: A prefix shorter than /96 cannot yield a site ID

- **WHEN** `SiteID("fd7a:115c:a1e0:b1a::/95")` is called
- **THEN** it returns `(0, false)`, because the site ID field is not fully
  addressed at that width

### Requirement: Via-range membership is checked independently of validity

The addrspace capability SHALL report whether a CIDR lies within the
Tailscale via range using only range membership and the via range's own
`/64` width, deliberately without requiring a `/96`-or-longer prefix or a
valid embedded site ID — so a malformed via prefix is distinguishable from an
ordinary, unrelated route.

#### Scenario: An in-range prefix with a reserved site ID is still a via prefix

- **WHEN** `IsViaPrefix` is given a via-range CIDR whose embedded site ID
  exceeds 65535
- **THEN** it returns `true`, even though `SiteID` on the same CIDR returns
  `(0, false)`
