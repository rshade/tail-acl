# Autogroup Specification

## Purpose

Enumerate the fixed vocabulary of Tailscale autogroups this package
understands — which ones are confirmable from the policy document alone,
which require a live user roster, and what each one matches — so every
caller sees the same autogroup semantics.

## Requirements

### Requirement: KnownAutogroup and role autogroups are mutually exclusive sets

`KnownAutogroup` SHALL report `true` only for the autogroups this package can
confirm from the policy document alone (`autogroup:self`,
`autogroup:member`, `autogroup:members`, `autogroup:tagged`,
`autogroup:internet`, and `autogroup:danger-all`). `IsRoleAutogroup` SHALL
report `true` only for the six autogroups resolved from a live user roster
(`autogroup:owner`, `autogroup:admin`, `autogroup:it-admin`,
`autogroup:network-admin`, `autogroup:billing-admin`, `autogroup:auditor`).
No autogroup SHALL be reported `true` by both functions, and an unrecognized
autogroup (including one Tailscale adds later) SHALL be reported `false` by
both.

#### Scenario: A role autogroup is never also a known-offline autogroup

- **WHEN** each of the six role autogroups is checked against both
  `KnownAutogroup` and `IsRoleAutogroup`
- **THEN** `IsRoleAutogroup` reports `true` and `KnownAutogroup` reports
  `false` for every one

### Requirement: autogroup:danger-all matches every query unconditionally

`Matcher.Matches` SHALL report `autogroup:danger-all` as matching any query,
including a tag, a user, a bare device address, and a public address,
restoring the pre-mitigation meaning of `"*"`.

#### Scenario: danger-all matches a tag, a user, and a public address alike

- **WHEN** `Matches("autogroup:danger-all", query, policy, source)` is
  called for `query` in `{"tag:web", "alice@example.com", "8.8.8.8"}`
- **THEN** it returns `true` for every one

### Requirement: autogroup:internet matches exactly the publicly routable addresses

`Matcher.Matches` SHALL report `autogroup:internet` as matching a query only
when it resolves, through `Hosts`/`IPSets` expansion, to at least one
globally-unicast address or prefix that is not private, not the Tailscale
CGNAT (`100.64.0.0/10`) or ULA (`fd7a:115c:a1e0::/48`) range, and not one of
the other reserved IPv4/IPv6 ranges (loopback, link-local, multicast, and
equivalents).

#### Scenario: A Tailscale CGNAT address does not match autogroup:internet

- **WHEN** `Matches("autogroup:internet", "100.101.102.103", policy, "")` is
  called
- **THEN** it returns `false`, even though the address is globally routable
  address-space-wise, because it lies in Tailscale's own CGNAT range

### Requirement: autogroup:self, member, members, and tagged settle from the query's shape alone

`Matcher.Matches` SHALL report `autogroup:self` as matching only when query
equals source and looks like a user login. `autogroup:member` and
`autogroup:members` SHALL match any query that looks like a user login,
regardless of tag. `autogroup:tagged` SHALL match any query with the `tag:`
prefix.

#### Scenario: autogroup:self rejects a different user than the requester

- **WHEN** `Matches("autogroup:self", "alice@example.com", policy,
  "bob@example.com")` is called
- **THEN** it returns `false`

### Requirement: Role autogroups match only a roster-confirmed user, case-insensitively

`Matcher.Matches` SHALL report a role autogroup (e.g. `autogroup:admin`) as
matching a query only when the matcher was built with `HaveRoles: true`, the
query looks like a user login, and that login — compared after lowercasing
both the query and the stored keys — holds exactly that role in `Roles`; an
empty stored role SHALL never be treated as a match for any login absent
from the roster. A tag or bare device address SHALL never match a role
autogroup.

#### Scenario: A login's role match is case-insensitive

- **WHEN** `Roles` maps `"ada@example.com"` to `UserRoleAdmin` and
  `Matches("autogroup:admin", "ADA@Example.com", policy, "")` is called with
  `HaveRoles: true`
- **THEN** it returns `true`

#### Scenario: An absent login never matches through an empty stored role

- **WHEN** `HaveRoles` is `true` and a login absent from `Roles` is queried
  against any role autogroup
- **THEN** it returns `false`, because an unset role is rejected outright
  rather than compared against the zero value
