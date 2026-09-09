# Selector Specification

## Purpose

Resolve one Tailscale policy selector against a query identity using only
what the policy document supplies — the wildcard, exact identity, nested
groups, and Hosts/IPSets-expanded addresses — as the roster-blind boolean
matching engine the tri-state resolvers in this package are built on.

## Requirements

### Requirement: The wildcard and exact-string forms match before anything else is consulted

`Matcher.Matches` SHALL report a match when selector is exactly `"*"` or
equal to query, without expanding groups or addresses for either case.
`Matcher.AnyMatches` SHALL report a match when any selector in the list
matches, and SHALL report no match for a nil or empty list.

#### Scenario: The wildcard matches any query

- **WHEN** `Matches("*", "tag:web", "")` is called
- **THEN** it returns `true`

### Requirement: Nested group membership resolves through cycles without a false match

`Matcher.Matches` SHALL resolve a `group:` selector by testing every member
recursively, so a group naming another group settles through that nesting,
while a selector already on the current resolution path SHALL be treated as
contributing no further members, terminating a cycle as a definite
non-match rather than infinite recursion or a spurious match.

#### Scenario: A nested group member matches transitively

- **WHEN** `group:eng` contains `group:ops`, which contains
  `bob@example.com`, and `Matches("group:eng", "bob@example.com", "")` is
  called
- **THEN** it returns `true`

#### Scenario: A self-referential group terminates as a non-match

- **WHEN** `group:cycle` is defined as `{"group:cycle"}` and
  `Matches("group:cycle", "eve@example.com", "")` is called
- **THEN** it returns `false` rather than recursing indefinitely

### Requirement: Hosts and IPSets expand transitively, with cycle protection, before address containment

`ExpandAddressSelector` SHALL resolve a selector through `Policy.Hosts` and
`Policy.IPSets` to the concrete addresses or prefixes it ultimately names,
following a `Hosts` alias to another `Hosts` entry transitively, expanding
every member of an `IPSets` entry, returning a selector matching neither
form unchanged, and returning no values for a cycle rather than recursing
indefinitely. `AddressContains` SHALL report whether one address-or-prefix
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

### Requirement: LooksLikeUser distinguishes a login from a group or tag

`LooksLikeUser` SHALL report `true` only for a value containing `"@"` that
does not also begin with the `group:` prefix, so a group name that happens
to contain `@` is not misclassified as a user login.

#### Scenario: A group name containing "@" is not a user

- **WHEN** `LooksLikeUser("group:eng@example.com")` is called
- **THEN** it returns `false`

### Requirement: SelectorMatches is the roster-blind convenience entry point

`SelectorMatches(selector, query, policy, source)` SHALL report the same
result as constructing a `Matcher{Policy: policy}` with no roster and
calling `Matches(selector, query, source)` on it, so a role autogroup never
matches through this entry point.

#### Scenario: A role autogroup never matches through SelectorMatches

- **WHEN** `SelectorMatches("autogroup:admin", "ada@example.com", policy,
  "")` is called with no roster supplied
- **THEN** it returns `false`, because role resolution requires a `Matcher`
  built with a roster
