# Resolvable Spec Delta

## ADDED Requirements

### Requirement: A cross-tailnet selector is decidable only as an undeclared alias

A cross-tailnet `group://<alias>/<name>` or `tag://<alias>/<name>` selector
names members of another tailnet, whose roster this policy document cannot
supply. The tri-state resolvers SHALL therefore return `Unresolvable` for
such a selector, except in the single case where the non-match is decidable
from local evidence alone:

- The selector is well-formed **and** the matcher reports the policy's
  external-tailnet declarations read **and** the selector's alias is not
  among them — then the reference names nobody by local evidence, exactly as
  an undefined `group:` does, and the resolvers SHALL return `NoMatch`.

In every other case they SHALL return `Unresolvable`: when the alias is
declared, when the external-tailnet declarations were not read (so an absent
alias is indistinguishable from an unparsed field), and when the selector
uses the cross-tailnet grammar but is malformed — a mistyped cross-tailnet
reference must not read as "this rule covers nothing".

A matcher SHALL NOT refute a declared cross-tailnet selector from the shape
of the query. Unlike a tag, which provably has no user owner and so refutes
a role autogroup, no local query shape carries certainty about an external
tailnet's identities.

#### Scenario: A declared alias is undecidable

- **WHEN** a matcher whose policy declares external tailnet `partner`, with
  the declarations reported read, resolves
  `MatchesTri("group://partner/engineering", "ada@example.com", "")`
- **THEN** it returns `Unresolvable`

#### Scenario: An undeclared alias is a decidable non-match once declarations are read

- **WHEN** that same matcher resolves
  `MatchesTri("group://typo/engineering", "ada@example.com", "")`
- **THEN** it returns `NoMatch`, because `typo` is not among the policy's
  declared external tailnets

#### Scenario: An undeclared alias is undecidable when declarations were not read

- **WHEN** a matcher that reports the external-tailnet declarations unread
  resolves `MatchesTri("group://typo/engineering", "ada@example.com", "")`
- **THEN** it returns `Unresolvable`, because an absent alias cannot be told
  apart from a field the caller never parsed

#### Scenario: A malformed cross-tailnet selector is undecidable either way

- **WHEN** `MatchesTri("group://partner", "ada@example.com", "")` is
  resolved on a matcher with the declarations read and again on one without
- **THEN** both return `Unresolvable`

#### Scenario: A tag query does not refute a declared cross-tailnet selector

- **WHEN** a matcher with `partner` declared and the declarations read
  resolves `MatchesTri("tag://partner/batch", "tag:web", "")`
- **THEN** it returns `Unresolvable`, not `NoMatch`

## MODIFIED Requirements

### Requirement: MatchesTri reports Matched, NoMatch, or Unresolvable by decidability

`Matcher.MatchesTri` SHALL return `Matched` whenever `Matches` reports a
match. Otherwise it SHALL return `Unresolvable` when the selector cannot be
decided against the query's shape and the matcher's available facts (per
`AutogroupResolvable`'s rule, extended through any group the selector
expands to and across the cross-tailnet vocabulary), or when the selector
names an `IPSets` entry that cannot be materialized under the ipset grammar,
and `NoMatch` only when the non-match is decidable. An ipset that
materializes to no address space is decidable: a query against it is
`NoMatch`.

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

#### Scenario: A cross-tailnet selector is not reported as a confident non-match

- **WHEN** `MatchesTri("group://partner/engineering", "ada@example.com",
  policy, source)` is called on a policy declaring `partner`
- **THEN** it returns `Unresolvable`, not the `NoMatch` an unrecognized
  selector would previously have produced

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
independently settle. The same SHALL hold for a `Groups` key spelled as a
cross-tailnet selector: expanding it locally SHALL NOT settle the
cross-tailnet reading.

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

#### Scenario: A Groups key shadowing a cross-tailnet selector keeps it undecidable

- **WHEN** a policy declares external tailnet `partner`, defines
  `Groups["group://partner/engineering"] = ["alice@example.com"]`, and
  `MatchesTri("group://partner/engineering", "bob@example.com", policy,
  source)` is called
- **THEN** it returns `Unresolvable`, because the cross-tailnet reading is
  still unsettled even though the local group reading is a definite
  non-match

#### Scenario: A group naming a cross-tailnet selector becomes undecidable

- **WHEN** `group:mixed` contains `["ada@example.com",
  "group://partner/engineering"]` on a policy declaring `partner`, and
  `MatchesTri("group:mixed", "bob@example.com", policy, source)` is called
- **THEN** it returns `Unresolvable`, while the same call for
  `"ada@example.com"` returns `Matched`, because a definite member match
  outranks the undecidable sibling

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

Having no policy document, it also holds no external-tailnet declarations,
so it SHALL report every cross-tailnet selector as undecidable. A matcher
that has read those declarations SHALL settle the undeclared-alias case, as
it settles the roster case.

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

#### Scenario: A cross-tailnet selector is undecidable with no policy document

- **WHEN** `AutogroupResolvable("group://partner/engineering",
  "ada@example.com")` is called
- **THEN** it returns `false`

### Requirement: Recognized reports whether a non-match is conclusive

`Matcher.Recognized` SHALL report `true` for every selector that is neither
an autogroup nor a cross-tailnet selector, except one that names an `IPSets`
entry that cannot be materialized under the ipset grammar, for which it
SHALL report `false`.

For an autogroup, it SHALL report `true` when `KnownAutogroup` reports
`true`, or when the autogroup is a role autogroup and the matcher has
`HaveRoles: true`; otherwise it SHALL report `false`, so a caller with no
roster treats a role-autogroup non-match as "coverage may be understated"
rather than "genuinely absent."

For a cross-tailnet selector, it SHALL report `true` only when the selector
is well-formed, the matcher reports the policy's external-tailnet
declarations read, and the alias is not among them — the one case whose
non-match is conclusive. It SHALL report `false` otherwise, including for a
declared alias and for a malformed selector.

#### Scenario: A role autogroup is unrecognized without a roster and recognized with one

- **WHEN** `Recognized("autogroup:admin")` is called on a matcher with no
  roster and again on an otherwise-identical matcher with `HaveRoles: true`
- **THEN** the first call returns `false` and the second returns `true`

#### Scenario: An unmaterializable ipset is unrecognized and a valid one is recognized

- **WHEN** `Recognized("ipset:broken")` is called where `ipset:broken` is
  `["host:missing"]` with no such host, and `Recognized("ipset:trimmed")` is
  called where `ipset:trimmed` is `["add 10.0.0.0/8", "remove 10.1.0.0/16"]`
- **THEN** the first call returns `false` and the second returns `true`

#### Scenario: A declared cross-tailnet alias is not recognized, an undeclared one is

- **WHEN** `Recognized("group://partner/engineering")` and
  `Recognized("group://typo/engineering")` are called on a matcher declaring
  `partner` with the declarations reported read
- **THEN** the first returns `false` and the second returns `true`

#### Scenario: No cross-tailnet selector is recognized when declarations were not read

- **WHEN** `Recognized("group://partner/engineering")` is called on a matcher
  reporting the external-tailnet declarations unread
- **THEN** it returns `false`

### Requirement: SelectorMatchesTri and AnySelectorMatchesTri are the zero-roster Matcher

`SelectorMatchesTri(selector, query, policy, source)` SHALL take the pinned
SDK's ACL and return exactly what a `Matcher` over a policy container
wrapping that ACL — with no roster and no external-tailnet declarations read
— returns from `MatchesTri(selector, query, source)`, and
`AnySelectorMatchesTri` SHALL agree likewise with that same matcher's
`AnyMatchesTri`, for every selector form including wildcards, tags, groups,
hosts, every autogroup, and every cross-tailnet selector.

#### Scenario: The package-level and zero-roster method forms agree on a role autogroup

- **WHEN** `SelectorMatchesTri("autogroup:admin", "ada@example.com", policy,
  source)` and the equivalent zero-roster `Matcher`'s
  `MatchesTri("autogroup:admin", "ada@example.com", source)` are both called
- **THEN** they return the identical `Match` value

#### Scenario: The package-level form reports a cross-tailnet selector unresolvable

- **WHEN** `SelectorMatchesTri("group://partner/engineering",
  "ada@example.com", policy, source)` is called
- **THEN** it returns `Unresolvable`, because a container built from an ACL
  alone reports no external-tailnet declarations read
