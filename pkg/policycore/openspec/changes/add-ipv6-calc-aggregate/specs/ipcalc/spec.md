# Ipcalc Spec Delta

## RENAMED Requirements

- FROM: `### Requirement: IPv4 prefixes aggregate to a minimal deterministic cover`
- TO: `### Requirement: Prefixes aggregate to a minimal deterministic cover`

## MODIFIED Requirements

### Requirement: Prefixes aggregate to a minimal deterministic cover

The ipcalc capability SHALL reduce a non-empty set of valid IPv4 and IPv6
prefixes to the minimal set of normalized CIDRs that covers exactly the same
addresses. It SHALL discard duplicate and covered prefixes, recursively
combine sibling prefixes when their parent is fully covered, and return the
resulting prefixes in ascending network-address order. A prefix SHALL never
merge with, or be discarded as covered by, a prefix of the other address
family, and every IPv4 result SHALL precede every IPv6 result.

#### Scenario: Adjacent siblings merge

- **WHEN** the input contains `10.0.0.0/25` and `10.0.0.128/25`
- **THEN** the result contains exactly `10.0.0.0/24`

#### Scenario: Covered prefixes do not duplicate the cover

- **WHEN** the input contains `10.0.0.0/24` and `10.0.0.0/25`
- **THEN** the result contains exactly `10.0.0.0/24`

#### Scenario: Multi-level merge reaches the shared parent

- **WHEN** the input contains the four `/26` children of `10.0.0.0/24`
- **THEN** the result contains exactly `10.0.0.0/24`

#### Scenario: Disjoint prefixes remain distinct and ordered

- **WHEN** the input contains `10.1.0.0/24` and `10.0.0.0/24`
- **THEN** the result contains `10.0.0.0/24` followed by `10.1.0.0/24`

#### Scenario: Adjacent IPv6 siblings merge

- **WHEN** the input contains `2001:db8:0:8000::/49` and `2001:db8::/49`
- **THEN** the result contains exactly `2001:db8::/48`

#### Scenario: ULA blocks merge across levels

- **WHEN** the input contains `fd12:3456:789a:1::/64`,
  `fd12:3456:789a:2::/63`, and `fd12:3456:789a::/64`
- **THEN** the result contains exactly `fd12:3456:789a::/62`

#### Scenario: Wide IPv6 prefixes cover their descendants

- **WHEN** the input contains `2000::/3`, `2001:db8::/32`, and `3ffe::/16`
- **THEN** the result contains exactly `2000::/3`

#### Scenario: Unmergeable IPv6 prefixes stay separate and ordered

- **WHEN** the input contains `2001:db8:2::/48` and `2001:db8::/48`
- **THEN** the result contains `2001:db8::/48` followed by `2001:db8:2::/48`

#### Scenario: Mixed families never merge and order IPv4 first

- **WHEN** the input contains `2001:db8::/49`, `10.0.0.128/25`,
  `2001:db8:0:8000::/49`, and `10.0.0.0/25`
- **THEN** the result contains `10.0.0.0/24` followed by `2001:db8::/48`
