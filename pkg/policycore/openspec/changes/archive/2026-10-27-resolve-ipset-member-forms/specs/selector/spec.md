# Selector Delta

## MODIFIED Requirements

### Requirement: Hosts and IPSets expand transitively, with cycle protection, before address containment

`ExpandAddressSelector` SHALL resolve a selector through `Policy.Hosts` and
`Policy.IPSets` to the concrete addresses or prefixes it ultimately names,
following a `Hosts` alias to another `Hosts` entry transitively, returning a
selector matching neither form unchanged, and returning no values for a
`Hosts` cycle rather than recursing indefinitely. A selector that names an
`IPSets` entry SHALL expand to the prefixes that set materializes to under
the ipset grammar — operations applied in order, ranges expanded, `host:`
references resolved, nested `ipset:` references recursed — rendered as
prefix strings, and SHALL expand to no values when the set cannot be
materialized. `AddressContains` SHALL report whether one address-or-prefix
value covers another, comparing a prefix against a wider prefix, a prefix
against an address, and two addresses for equality.

#### Scenario: A host alias resolves transitively to its CIDR

- **WHEN** `Hosts` maps `"alias"` to `"web"` and `"web"` to `"10.1.0.0/16"`,
  and `ExpandAddressSelector("alias", policy)` is called
- **THEN** it returns `["10.1.0.0/16"]`

#### Scenario: A cyclic host alias expands to nothing

- **WHEN** `Hosts` maps `"a"` to `"b"` and `"b"` to `"a"`, and
  `ExpandAddressSelector("a", policy)` is called
- **THEN** it returns an empty result rather than recursing indefinitely

#### Scenario: A host selector matches a query address it contains

- **WHEN** `Hosts` maps `"web"` to `"10.1.0.0/16"` and
  `Matches("web", "10.1.2.3", "")` is called
- **THEN** it returns `true`, because address expansion resolves `"web"` to
  its CIDR and `AddressContains` reports the query address covered

#### Scenario: An ipset with a remove operation matches what the add kept

- **WHEN** `Hosts` maps `gw` to `10.9.0.1`, `ipset:base` is `["10.0.0.0/8"]`,
  `ipset:trimmed` is `["add ipset:base", "remove 10.1.0.0/16"]`, `ipset:rng`
  is `["10.5.0.1-10.5.0.9"]`, `ipset:h` is `["host:gw"]`, and `Matches` is
  called for each set against a query address
- **THEN** `Matches("ipset:trimmed", "10.2.0.5", "")` is `true`,
  `Matches("ipset:trimmed", "10.1.0.5", "")` is `false`,
  `Matches("ipset:rng", "10.5.0.4", "")` is `true`, and
  `Matches("ipset:h", "10.9.0.1", "")` is `true`

#### Scenario: An unmaterializable ipset expands to nothing and matches nothing

- **WHEN** `ipset:broken` is `["host:missing"]` and no such host is defined
- **THEN** `ExpandAddressSelector("ipset:broken", policy)` returns an empty
  result and `Matches("ipset:broken", "10.0.0.1", "")` returns `false`
