# Selector Spec Delta

## ADDED Requirements

### Requirement: A Matcher resolves against a policy document, not a bare SDK ACL

`Matcher.Policy` SHALL name a policy document container that carries the
pinned SDK's ACL together with the policy fields that SDK does not model.
The container SHALL expose the ACL's `Groups`, `Hosts`, and `IPSets` for
matching exactly as before, and SHALL additionally carry the policy's
declared external-tailnet relationships plus a flag reporting whether those
declarations were actually read from the policy.

That flag SHALL distinguish "the policy declares no external tailnets" from
"the caller never read the field", the same distinction `HaveRoles` draws
for the user roster. A caller that does not parse external-tailnet
declarations SHALL leave it false.

A `Matcher` holding no policy document, and one holding a container that
wraps no ACL, SHALL be indistinguishable to every resolver: both SHALL name
no groups, hosts, or ipsets, and neither SHALL panic. The container makes the
second form newly constructible, so the two must not differ.

#### Scenario: Group, host, and ipset matching is unchanged by the container

- **WHEN** a `Matcher` is built over a policy container wrapping an ACL whose
  `Hosts` maps `"web"` to `"10.1.0.0/16"`, and `Matches("web", "10.1.2.3",
  "")` is called
- **THEN** it returns `true`, exactly as it did when `Policy` named the ACL
  directly

#### Scenario: A container wrapping no ACL resolves without panicking

- **WHEN** a `Matcher` whose policy container wraps a nil ACL is asked to
  resolve a `group:` selector
- **THEN** it reports no group membership rather than panicking, exactly as a
  `Matcher` holding no policy document at all does

### Requirement: Cross-tailnet selectors are a distinct vocabulary that never matches locally

`IsCrossTailnetSelector` SHALL report whether a selector uses the
cross-tailnet `group://<alias>/<name>` or `tag://<alias>/<name>` grammar,
returning `true` for a malformed selector that nonetheless uses that
grammar, so a mistyped cross-tailnet reference is never routed down the
local-selector path. It SHALL share one definition of the grammar with the
parser that consumes it, so no second list of selector forms exists to drift
out of sync.

`Matcher.Matches` SHALL NOT report a match on the cross-tailnet reading of
such a selector: the members it names live in another tailnet's policy, which
this matcher cannot consult, so no local fact can confirm them.

`Matches` resolves a selector as the union of its readings, so the other
readings keep their existing behavior and precedence: `"*"` still names every
query, a selector still names a query equal to it, and a policy that defines
a `Groups` key spelled as a cross-tailnet selector has defined a local group
whose members are still matched as such — exactly as a `Groups` key spelled
`autogroup:admin` is. What that local reading SHALL NOT do is settle the
cross-tailnet one, which stays undecidable.

`Matcher.KnownExternalTailnetAlias` SHALL report whether the matcher's
policy declares a given alias, and SHALL report `false` for every alias when
the external-tailnet declarations were not read.

#### Scenario: A Groups key spelled as a cross-tailnet selector matches its members

- **WHEN** a policy defines `Groups["group://partner/engineering"] =
  ["ada@example.com"]` and `Matches("group://partner/engineering",
  "ada@example.com", "")` is called
- **THEN** it returns `true` on the local group reading, while the same
  selector against a non-member stays undecidable

#### Scenario: A cross-tailnet selector does not match a local identity

- **WHEN** `Matches("group://partner/engineering", "ada@example.com", "")` is
  called on a policy that declares `partner` as an external tailnet
- **THEN** it returns `false`, because the named group's members are not
  described by this tailnet's policy

#### Scenario: A malformed cross-tailnet selector is still recognized as one

- **WHEN** `IsCrossTailnetSelector("group://partner")` and
  `IsCrossTailnetSelector("group:engineering")` are called
- **THEN** the first returns `true` and the second returns `false`

#### Scenario: A declared alias is known only when the declarations were read

- **WHEN** `KnownExternalTailnetAlias("partner")` is called on a matcher
  whose policy declares `partner` and reports the declarations read, and
  again on an otherwise-identical matcher that reports them unread
- **THEN** the first returns `true` and the second returns `false`

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
materialized. A nil policy document declares no aliases, so every selector
SHALL expand to itself unchanged rather than panicking — address expansion
runs on every selector that is not a group, so a panic there reaches every
caller of `Matches`. `AddressContains` SHALL report whether one
address-or-prefix value covers another, comparing a prefix against a wider
prefix, a prefix against an address, and two addresses for equality.

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

#### Scenario: A nil policy expands every selector to itself

- **WHEN** `ExpandAddressSelector("web", nil)` and
  `IsPublicAddress("8.8.8.8", nil)` are called
- **THEN** the first returns `["web"]` and the second returns `true`,
  neither panicking

### Requirement: SelectorMatches is the roster-blind convenience entry point

`SelectorMatches(selector, query, policy, source)` SHALL take the pinned
SDK's ACL and report the same result as constructing a `Matcher` over a
policy container that wraps that ACL, carries no roster, and reports no
external-tailnet declarations read, then calling `Matches(selector, query,
source)` on it. A role autogroup therefore never matches through this entry
point, and neither does a cross-tailnet selector.

#### Scenario: A role autogroup never matches through SelectorMatches

- **WHEN** `SelectorMatches("autogroup:admin", "ada@example.com", policy,
  "")` is called with no roster supplied
- **THEN** it returns `false`, because role resolution requires a `Matcher`
  built with a roster

#### Scenario: A cross-tailnet selector never matches through SelectorMatches

- **WHEN** `SelectorMatches("group://partner/engineering",
  "ada@example.com", policy, "")` is called
- **THEN** it returns `false`
