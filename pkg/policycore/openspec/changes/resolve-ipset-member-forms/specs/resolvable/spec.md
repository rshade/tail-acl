# Resolvable Delta

## MODIFIED Requirements

### Requirement: MatchesTri reports Matched, NoMatch, or Unresolvable by decidability

`Matcher.MatchesTri` SHALL return `Matched` whenever `Matches` reports a
match. Otherwise it SHALL return `Unresolvable` when the selector cannot be
decided against the query's shape and the matcher's available facts (per
`AutogroupResolvable`'s rule, extended through any group the selector
expands to), or when the selector names an `IPSets` entry that cannot be
materialized under the ipset grammar, and `NoMatch` only when the non-match
is decidable. An ipset that materializes to no address space is decidable:
a query against it is `NoMatch`.

#### Scenario: A role autogroup against a user with no roster is unresolvable

- **WHEN** `MatchesTri("autogroup:admin", "alice@example.com", policy,
  source)` is called with no roster available
- **THEN** it returns `Unresolvable`, not `NoMatch`

#### Scenario: A tag refutes a role autogroup with certainty even without a roster

- **WHEN** `MatchesTri("autogroup:admin", "tag:web", policy, source)` is
  called with no roster available
- **THEN** it returns `NoMatch`, because a tagged device has no user owner

#### Scenario: An unmaterializable ipset is unresolvable, an empty one is not

- **WHEN** `ipset:broken` is `["host:missing"]` with no such host defined,
  `ipset:empty` is `["add 203.0.113.0/24", "remove 203.0.113.0/24"]`, and
  `MatchesTri` is called for each against `203.0.113.7`
- **THEN** `ipset:broken` returns `Unresolvable` and `ipset:empty` returns
  `NoMatch`

#### Scenario: A group containing an unmaterializable ipset is unresolvable

- **WHEN** `group:net` contains `["ipset:broken"]`, `ipset:broken` cannot be
  materialized, and `MatchesTri("group:net", "10.0.0.1", policy, source)` is
  called
- **THEN** it returns `Unresolvable`

### Requirement: Recognized reports whether a non-match is conclusive

`Matcher.Recognized` SHALL report `true` for every non-autogroup selector
except one that names an `IPSets` entry that cannot be materialized under
the ipset grammar, for which it SHALL report `false`. For an autogroup, it
SHALL report `true` when `KnownAutogroup` reports `true`, or when the
autogroup is a role autogroup and the matcher has `HaveRoles: true`;
otherwise it SHALL report `false`, so a caller with no roster treats a
role-autogroup non-match as "coverage may be understated" rather than
"genuinely absent."

#### Scenario: A role autogroup is unrecognized without a roster and recognized with one

- **WHEN** `Recognized("autogroup:admin")` is called on a matcher with no
  roster and again on an otherwise-identical matcher with `HaveRoles: true`
- **THEN** the first call returns `false` and the second returns `true`

#### Scenario: An unmaterializable ipset is unrecognized and a valid one is recognized

- **WHEN** `Recognized("ipset:broken")` is called where `ipset:broken` is
  `["host:missing"]` with no such host, and `Recognized("ipset:trimmed")` is
  called where `ipset:trimmed` is `["add 10.0.0.0/8", "remove 10.1.0.0/16"]`
- **THEN** the first call returns `false` and the second returns `true`
