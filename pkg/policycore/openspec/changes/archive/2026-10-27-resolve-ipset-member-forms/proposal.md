# Proposal: resolve-ipset-member-forms

## Why

`ExpandAddressSelector` follows `Hosts` by bare alias and `IPSets` by name and
passes every other ipset member through verbatim. A member written in any of
the control plane's other forms — `add 10.0.0.0/8`, `remove 10.1.0.0/16`,
`10.5.0.1-10.5.0.9`, `host:gw` — never parses as a prefix downstream and
never matches, so `tail-acl check`/`test` return false denials and
`tailnet-audit` grades devices inside such sets as ungoverned. The grammar
those members follow already lives in this package (`ParseIPSetMember`, #364);
the resolver is the half that was deliberately left for a follow-up.
Issue #366 measured the defect against a policy the control plane enforces
exactly as written.

This is the `policycore` half of a change shared with `tail-acl` and
`tailnet-audit` under the slug `resolve-ipset-member-forms`.

## What Changes

- Add `ResolveIPSet`, which materializes one `IPSets` entry into the address
  space its members cover: every member is parsed with the ipset grammar,
  operations are applied in member order so a `remove` withdraws address
  space an earlier member contributed (including a `host:` alias whose
  address falls inside the removed range), ranges expand to prefixes, `host:`
  references resolve through `Hosts`, and `ipset:` references recurse with the
  same cycle, depth, and size limits `tail-ipam`'s resolver applies.
- `ExpandAddressSelector` materializes an `IPSets` entry through
  `ResolveIPSet` instead of walking its member strings. Its signature and its
  `Hosts` behavior are unchanged; an ipset that cannot be materialized expands
  to no values.
- An ipset that cannot be materialized — a member that does not parse, a
  `host:` or `ipset:` reference the policy does not define, a cycle, or an
  expansion past the limits — makes every selector that reaches it
  `Unresolvable` rather than `NoMatch`: `Matcher.MatchesTri` reports
  `Unresolvable` and `Matcher.Recognized` reports `false` for it. Consumers
  therefore report indeterminate (tail-acl) or caveat (tailnet-audit) instead
  of a confident denial the policy does not support.
- One accidental form stops resolving: a bare host alias written directly as
  an ipset member (`"ipset:x": ["gw"]`) expanded through `Hosts` before, but
  it is not a member the control plane or the grammar accepts, so it now
  makes the set unmaterializable and the verdict indeterminate rather than
  silently resolved. The control plane's spelling is `host:gw`.
- Known limit, carried not fixed: the control plane also accepts
  `autogroup:internet` as an ipset member (confirmed against
  `/acl/validate` on 2026-09-11) and the #364 grammar does not. A set
  containing it is unmaterializable under this change — indeterminate, not
  a false deny — and the grammar extension is #372.

## Capabilities

### New Capabilities

<!-- None. -->

### Modified Capabilities

- `ipset`: gains the materialization requirement — an ipset resolves to the
  address space its members cover, operations applied in order, and the
  conditions under which it cannot be materialized.
- `selector`: the Hosts/IPSets expansion requirement changes — an ipset is
  materialized through the member grammar rather than expanded member by
  member, so operations, ranges, and `host:` references resolve.
- `resolvable`: `MatchesTri` and `Recognized` treat a selector that reaches an
  unmaterializable ipset as undecidable rather than a settled non-match.

## Impact

- `policycore/address.go` (`ExpandAddressSelector`), a new resolver file,
  `policycore/resolvable.go` (`selectorResolvable`, `Recognized`),
  `docs/public-api.md`.
- `go4.org/netipx` moves from an indirect to a direct dependency of
  `policycore`; it is already in the module graph through `tailscale.com`.
- Every CLI module compiles `policycore` through a local `replace`, so the
  verdict change reaches `tail-acl check`/`test` and `tailnet-audit`'s policy
  coverage without a version bump. Those modules carry their own
  `resolve-ipset-member-forms` change for the surface each exposes.
- `tail-ipam` keeps its own resolver; the shared fixture parity test pins the
  two to one answer, and collapsing them is a later change.
