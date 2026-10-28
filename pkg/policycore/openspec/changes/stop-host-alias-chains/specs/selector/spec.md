# Selector Delta

## REMOVED Requirements

### Requirement: Hosts and IPSets expand transitively, with cycle protection, before address containment

**Reason**: The control plane rejects a `hosts` value that is not a literal
address or prefix, so transitive host resolution promises a result that
cannot deploy.

**Migration**: Read a `hosts` value as written. A literal address or prefix
is that literal. Any other value is unchanged and is not followed.

## ADDED Requirements

### Requirement: Hosts and IPSets expand to literal addresses before containment

`ExpandAddressSelector` SHALL return a `Hosts` value as written. A literal
address or prefix SHALL NOT be looked up again as a host name, and any other
value SHALL NOT be followed. An `IPSets` entry SHALL expand every member. A
selector matching neither SHALL be returned unchanged, and a cycle SHALL NOT
recurse indefinitely.

#### Scenario: A hosts value must be a literal address or prefix

- **WHEN** `Hosts` maps `"a"` to `"b"` and `"b"` to `"10.10.20.1"`, and
  `ExpandAddressSelector("a", policy)` is called
- **THEN** it returns `["b"]` and does not return `["10.10.20.1"]`

#### Scenario: A literal host value is returned and not looked up again

- **WHEN** `Hosts` maps `"web"` to `"10.1.0.0/16"`, and
  `ExpandAddressSelector("web", policy)` is called
- **THEN** it returns `["10.1.0.0/16"]`

#### Scenario: A cyclic host alias returns the immediate value

- **WHEN** `Hosts` maps `"a"` to `"b"` and `"b"` to `"a"`, and
  `ExpandAddressSelector("a", policy)` is called
- **THEN** it returns `["b"]` rather than recursing indefinitely

#### Scenario: A host selector matches a query address it contains

- **WHEN** `Hosts` maps `"web"` to `"10.1.0.0/16"` and
  `Matches("web", "10.1.2.3", "")` is called
- **THEN** it returns `true`, because address expansion resolves `"web"` to
  its CIDR and that CIDR covers the query address

### Requirement: Address containment compares prefixes and addresses

`AddressContains` SHALL report whether one address-or-prefix value covers
another, comparing a prefix against a wider prefix, a prefix against an
address, and two addresses for equality.

#### Scenario: A prefix covers an address inside it

- **WHEN** `AddressContains("10.1.0.0/16", "10.1.2.3")` is called
- **THEN** it returns `true`
