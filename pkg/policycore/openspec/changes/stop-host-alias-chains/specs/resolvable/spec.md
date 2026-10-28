# Resolvable Delta

## MODIFIED Requirements

### Requirement: Recognized reports whether a non-match is conclusive

`Matcher.Recognized` SHALL report `true` for every non-autogroup selector,
except a host whose value is not a literal address or prefix, which SHALL
be reported `false`. For an autogroup, it SHALL report `true` when
`KnownAutogroup` reports `true`, or when the autogroup is a role autogroup
and the matcher has `HaveRoles: true`; otherwise it SHALL report `false`,
so a caller with no roster treats a role-autogroup non-match as "coverage
may be understated" rather than "genuinely absent."

#### Scenario: A role autogroup is unrecognized without a roster and recognized with one

- **WHEN** `Recognized("autogroup:admin")` is called on a matcher with no
  roster and again on an otherwise-identical matcher with `HaveRoles: true`
- **THEN** the first call returns `false` and the second returns `true`

#### Scenario: A non-literal host is unrecognized

- **WHEN** `Hosts` maps `"a"` to `"b"` and `Recognized("a")` is called
- **THEN** it returns `false`

#### Scenario: A literal host stays recognized

- **WHEN** `Hosts` maps `"web"` to `"10.1.0.0/16"` and `Recognized("web")`
  is called
- **THEN** it returns `true`

## ADDED Requirements

### Requirement: A non-literal host is undecidable

`MatchesTri` SHALL return `Unresolvable`, not `NoMatch`, when a host's value
is not a literal address or prefix and the selector does not match the query
by exact equality. A host whose value is a literal address or prefix SHALL
stay decidable.

#### Scenario: An alias chain is not a confident denial

- **WHEN** `Hosts` maps `"a"` to `"b"` and `"b"` to `"10.10.20.1"`, and
  `MatchesTri("a", "10.10.20.1", policy, source)` is called
- **THEN** it returns `Unresolvable`, not `NoMatch`

#### Scenario: A literal host still matches an address it contains

- **WHEN** `Hosts` maps `"web"` to `"10.1.0.0/16"` and
  `MatchesTri("web", "10.1.2.3", policy, source)` is called
- **THEN** it returns `Matched`

#### Scenario: A literal host that misses the query is a denial

- **WHEN** `Hosts` maps `"web"` to `"10.1.0.0/16"` and
  `MatchesTri("web", "11.0.0.1", policy, source)` is called
- **THEN** it returns `NoMatch`
