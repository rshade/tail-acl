# ipcalc CIDR Aggregation Delta

## ADDED Requirements

### Requirement: IPv4 prefixes aggregate to a minimal deterministic cover

The ipcalc capability SHALL reduce a non-empty set of valid IPv4 prefixes to
the minimal set of normalized CIDRs that covers exactly the same addresses.
It SHALL discard duplicate and covered prefixes, recursively combine sibling
prefixes when their parent is fully covered, and return the resulting prefixes
in ascending network-address order.

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
