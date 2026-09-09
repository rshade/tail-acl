# Resolvable Specification

## Purpose

Add a third verdict, `Unresolvable`, to selector matching: when the answer
depends on control-plane state a matcher does not hold, report that
explicitly instead of collapsing "cannot tell" into a confident `NoMatch`,
which is the one wrong answer a reachability or coverage verdict must never
produce.

## Requirements

### Requirement: MatchesTri reports Matched, NoMatch, or Unresolvable by decidability

`Matcher.MatchesTri` SHALL return `Matched` whenever `Matches` reports a
match. Otherwise it SHALL return `Unresolvable` when the selector cannot be
decided against the query's shape and the matcher's available facts (per
`AutogroupResolvable`'s rule, extended through any group the selector
expands to), and `NoMatch` only when the non-match is decidable.

#### Scenario: A role autogroup against a user with no roster is unresolvable

- **WHEN** `MatchesTri("autogroup:admin", "alice@example.com", policy,
  source)` is called with no roster available
- **THEN** it returns `Unresolvable`, not `NoMatch`

#### Scenario: A tag refutes a role autogroup with certainty even without a roster

- **WHEN** `MatchesTri("autogroup:admin", "tag:web", policy, source)` is
  called with no roster available
- **THEN** it returns `NoMatch`, because a tagged device has no user owner

### Requirement: Undecidability propagates through nested groups, and a definite match outranks it

When a `group:` selector's members are evaluated for `MatchesTri`, an
`Unresolvable` result from any member SHALL make the whole group
`Unresolvable` unless some other member produces a definite `Matched`, in
which case the match wins regardless of an undecidable sibling. This holds
through multiple levels of group nesting, through a diamond of shared
sub-groups, and through a self-referential cycle, which SHALL still
terminate as a definite non-match contributing no undecidability of its own.
A `Groups` key that happens to collide with an autogroup name (e.g. a policy
defining `Groups["autogroup:admin"]`) SHALL NOT make that autogroup's
roster-dependent reading decidable — `Matches` resolves a selector as the
union of its direct-match and group-member readings, so both readings must
independently settle.

#### Scenario: A definite member match outranks an undecidable sibling

- **WHEN** `group:match-wins` contains `["autogroup:tagged", "100.64.0.9"]`
  and `MatchesTri("group:match-wins", "100.64.0.9", policy, source)` is
  called
- **THEN** it returns `Matched`, because the literal address member settles
  the group even though `autogroup:tagged` cannot

#### Scenario: A diamond of shared sub-groups still propagates undecidability once

- **WHEN** `group:diamond` contains `group:left` and `group:right`, both of
  which contain `group:shared`, which contains `autogroup:tagged`, and
  `MatchesTri("group:diamond", "100.64.0.9", policy, source)` is called
- **THEN** it returns `Unresolvable`

#### Scenario: A self-referential cycle contributes no undecidability of its own

- **WHEN** `group:cycle-unknown` contains `["group:cycle-unknown",
  "autogroup:tagged"]` and `MatchesTri("group:cycle-unknown", "100.64.0.9",
  policy, source)` is called
- **THEN** it returns `Unresolvable` solely because of the sibling
  `autogroup:tagged` member — the self-referential member is skipped as
  contributing nothing, not counted as its own source of undecidability

#### Scenario: A Groups key shadowing an autogroup name keeps the autogroup undecidable

- **WHEN** a policy defines `Groups["autogroup:admin"] =
  ["alice@example.com"]` and `MatchesTri("autogroup:admin",
  "bob@example.com", policy, source)` is called with no roster
- **THEN** it returns `Unresolvable`, not the group reading's `NoMatch`,
  because the roster-dependent autogroup reading is still unsettled

### Requirement: AnyMatchesTri lets a later match outrank an earlier unresolvable selector

`Matcher.AnyMatchesTri` (and its roster-blind counterpart
`AnySelectorMatchesTri`) SHALL return `Matched` if any selector in the list
matches, even when an earlier selector in the list was undecidable. When no
selector matches and at least one is undecidable, it SHALL return
`Unresolvable` together with the first such selector, as the reason a caller
surfaces. When every selector is decidable and none matches, it SHALL return
`NoMatch` with an empty reason.

#### Scenario: A later definite match outranks an earlier unresolvable selector

- **WHEN** `AnyMatchesTri(["autogroup:admin", "tag:web"], "tag:web", source)`
  is called with no roster
- **THEN** it returns `(Matched, "")`

#### Scenario: The first undecidable selector is named when nothing matches

- **WHEN** `AnyMatchesTri(["tag:db", "autogroup:admin",
  "autogroup:shared"], "alice@example.com", source)` is called with no
  roster
- **THEN** it returns `(Unresolvable, "autogroup:admin")`

### Requirement: AutogroupResolvable decides from the query's shape, not the selector alone

`AutogroupResolvable(selector, query)` SHALL report whether membership can be
settled without control-plane state, as a property of the (selector, query)
pair: `autogroup:tagged` is decidable against a tag or a user but not
against a bare device address, since only the control plane's device-to-tag
map could refute it there. A role autogroup's decidability against a user
additionally depends on whether a roster is available, which
`AutogroupResolvable` (having no roster) always answers as unavailable; a
`Matcher.MatchesTri` call with `HaveRoles: true` SHALL settle that same case.
It SHALL correctly walk `group:` selectors even against a `Matcher` holding
no `Policy`, reporting no group membership rather than panicking.

#### Scenario: autogroup:tagged is decidable against a tag but not a bare device

- **WHEN** `AutogroupResolvable("autogroup:tagged", "tag:db")` and
  `AutogroupResolvable("autogroup:tagged", "100.64.0.9")` are both called
- **THEN** the first returns `true` and the second returns `false`

#### Scenario: A roster settles a role autogroup against a user but never against a device

- **WHEN** a `Matcher` with `HaveRoles: true` calls
  `MatchesTri("autogroup:admin", "ada@example.com", "")` and
  `MatchesTri("autogroup:admin", "100.64.0.9", "")`
- **THEN** the first is not `Unresolvable` and the second is `Unresolvable`,
  because a login-to-role roster cannot identify a device's owner

### Requirement: Recognized reports whether a non-match is conclusive

`Matcher.Recognized` SHALL report `true` for every non-autogroup selector.
For an autogroup, it SHALL report `true` when `KnownAutogroup` reports
`true`, or when the autogroup is a role autogroup and the matcher has
`HaveRoles: true`; otherwise it SHALL report `false`, so a caller with no
roster treats a role-autogroup non-match as "coverage may be understated"
rather than "genuinely absent."

#### Scenario: A role autogroup is unrecognized without a roster and recognized with one

- **WHEN** `Recognized("autogroup:admin")` is called on a matcher with no
  roster and again on an otherwise-identical matcher with `HaveRoles: true`
- **THEN** the first call returns `false` and the second returns `true`

### Requirement: SelectorMatchesTri and AnySelectorMatchesTri are the zero-roster Matcher

`SelectorMatchesTri(selector, query, policy, source)` SHALL return exactly
what `Matcher{Policy: policy}.MatchesTri(selector, query, source)` returns,
and `AnySelectorMatchesTri` SHALL agree likewise with
`Matcher{Policy: policy}.AnyMatchesTri`, for every selector form including
wildcards, tags, groups, hosts, and every autogroup.

#### Scenario: The package-level and zero-roster method forms agree on a role autogroup

- **WHEN** `SelectorMatchesTri("autogroup:admin", "ada@example.com", policy,
  source)` and `Matcher{Policy: policy}.MatchesTri("autogroup:admin",
  "ada@example.com", source)` are both called
- **THEN** they return the identical `Match` value
