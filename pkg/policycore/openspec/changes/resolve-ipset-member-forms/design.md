# Design: resolve-ipset-member-forms

## Context

See proposal.md. Two resolvers exist today: `expandAddressSelectorSeen` in
this package, which walks member strings and knows nothing of the grammar,
and `tail-ipam/internal/policycheck`'s `resolver`, which applies the full
grammar with a memo, a path-scoped cycle guard, a nesting limit of 128, and
an expansion cap of 65536 prefixes. `ParseIPSetMember` (#364) already lifted
the syntax here; this change lifts the resolution and leaves `tail-ipam`'s
copy in place.

`Matcher` has a third verdict, `Unresolvable`, decided by
`selectorResolvable` for role autogroups and cross-tailnet aliases. The
resolver's failure modes need a home in that vocabulary, because the
alternatives — pass the raw member through (today's false deny) or drop it
(a `remove` that fails silently widens the set: a false allow) — are both
confident wrong answers.

### Wire evidence (2026-09-12)

A probe policy was uploaded to `example.ts.net` (ETag-guarded, then
restored; `plan` back to `no changes`) with five ipsets as grant
destinations on distinct ports, and the packet filter control pushed to the
`tail-ipam-smoke` subnet router (`tailscale debug netmap`,
`PacketFilterRules`, `Cached: false`) was captured 3 s later:

| set | members | control-sent `DstPorts` | node-compiled `Dsts` |
| --- | --- | --- | --- |
| 19366 | `add 10.10.20.0/23`, `remove 10.10.21.0/24` | `10.10.20.0/24` | `10.10.20.0/24` |
| 19367 | `10.10.20.1-10.10.20.9` | the range literal | `/32`, `/31`, `/30`, `/31` |
| 19368 | `host:gw` (`10.10.20.1`) | `10.10.20.1` | `10.10.20.1/32` |
| 19369 | `add host:gw`, `remove 10.10.20.0/24` | absent | absent |
| 19370 | `add /23`, `remove 10.10.20.0/24`, `add 10.10.20.1` | `10.10.20.1`, `10.10.21.0/24` | same |

So: a `remove` withdraws a `host:` alias's address; a later `add`
re-contributes; subtraction is exact; and the node compiles a range into the
same minimal prefix covering `netipx.IPSetBuilder` yields. The control plane
itself ships address specs after applying operations rather than a merged
prefix set, but enforcement happens on the node's compiled form, which is
what this resolver reproduces.

## Goals / Non-Goals

**Goals:**

- One resolver that materializes an ipset the way the control plane enforces
  it, with the same limits `tail-ipam` already applies, so the two tools
  cannot disagree about the effective address space of one set.
- A failure to materialize is undecidable, not a settled non-match, so every
  consumer that already honours `Unresolvable` gets the honest verdict for
  free.
- `ExpandAddressSelector`'s signature and `Hosts` semantics survive: every
  existing caller keeps compiling and every existing scenario keeps passing.

**Non-Goals:**

- Adopting this resolver in `tail-ipam`. Its `subtract` deliberately
  preserves each addition's boundaries for pool comparison; this resolver
  merges, because containment is the only question asked here.
- IPv4-mapped IPv6 equivalence. `AddressContains` does not unmap today and
  the control plane does not either.
- Linting an unmaterializable set at authoring time. `tail-acl lint` can
  adopt `ResolveIPSet` later; this change only makes the resolver's answer
  honest.

## Decisions

- **`ResolveIPSet(name, policy) ([]netip.Prefix, error)` is the primitive;
  `ExpandAddressSelector` wraps it.** The error is what distinguishes a set
  that materializes to nothing (`add X`, `remove X`) from one that cannot be
  materialized, and `selectorResolvable` needs exactly that distinction.
  Exporting it also gives `tail-acl lint` a hook without a second resolver.
  Alternative: change `ExpandAddressSelector` to return an error — rejected,
  it would ripple through `Matches` (a `bool`) and every caller of it.

- **Materialization uses `netipx.IPSetBuilder`, applied in member order.**
  Add contributes a prefix, a range, a resolved host, or a nested set; remove
  withdraws the same. The builder's `Prefixes()` output is the canonical,
  minimal, sorted covering — merged where members abut. This is what the
  proposal in #366 asks for, and it is the right shape for containment.
  `tail-ipam` keeps boundary-preserving subtraction because it answers a
  different question (which authored CIDR sits in which pool).

- **`host:` inside an ipset is exactly one `Hosts` lookup, and the value
  must be a literal address or prefix.** The control plane rejects a `Hosts`
  value that is not one (`ParseAddr("b"): unable to parse IP`, probed
  2026-09-11 via `/acl/validate`), so an alias chain inside an ipset is
  unmaterializable here too. `ExpandAddressSelector`'s bare-alias path keeps
  its transitive walk because the `selector` spec requires it and no caller
  asked for that to change; the discrepancy is #374. A `remove
  10.9.0.0/24` after `add host:gw` withdraws `gw`'s address because the
  alias was materialized before the subtraction ran — the control plane
  holds `deny` for exactly that assertion.

- **A bare alias is not an ipset member.** The control plane rejects
  `"gw"` outright (`rejected address "gw"; supported types are host name
  (host:example), IP set name (ipset:example), autogroup:internet, IP
  prefix, IP range, or IP`); only `"host:gw"` names a host. The old walk
  accepted the bare form by accident. Routing every member through
  `ParseIPSetMember` closes that gap and makes such a set unmaterializable.
  Alternative: special-case bare aliases for compatibility — rejected, the
  control plane refuses the policy, and pretending otherwise is the
  disagreement `policycore` exists to prevent.

- **`autogroup:internet` is a member the wire accepts and the grammar does
  not.** The same rejection message lists it, and `/acl/validate` accepts
  both `["autogroup:internet"]` and `["add autogroup:internet", "remove
  8.8.8.0/24"]`. `ParseIPSetMember` (#364) rejects it, so under this change
  a set containing it is unmaterializable and every verdict through it is
  indeterminate — honest, and strictly better than today's false deny.
  Teaching the grammar, `ipset add`, and this resolver the form is #372; it
  is not folded in here because it
  changes the `ipset` capability's parse contract, which #365 authors
  against.

- **Failure to materialize is `Unresolvable`.** `selectorResolvable` returns
  false for a selector that names an `IPSets` key whose `ResolveIPSet`
  errors, and `Recognized` does the same. `Matches` (boolean) reports no
  match, as it does for every undecidable selector, so no caller gains a
  false allow. The reasons are the seven `tail-ipam` reports: a member that
  does not parse, an implicit member beside a `remove` (the
  explicit-operation rule `ValidateIPSetOperations` already enforces for
  `ipset add` and `lint`), an undefined `host:` alias or a `Hosts` value
  that is not a literal address or prefix, an undefined `ipset:` reference,
  a cyclic `ipset:` reference, nesting deeper than 128, and expansion past
  65536 prefixes. This is the decision that goes beyond #366's literal text;
  the alternatives are the two confident wrong answers in Context.

- **The cycle guard is path-scoped, and the memo is per call.** As in
  `tail-ipam`: a set on the current resolution path is a cycle, a set
  already resolved in this call is served from the memo, and a diamond
  (`a` → `b`, `a` → `c`, `b` → `d`, `c` → `d`) resolves `d` once. Depth is
  counted per path so a memo hit cannot hide a chain that exceeds the limit.
  `Hosts` cycles keep the existing behaviour — they expand to nothing and
  are not an ipset failure — because that requirement already exists in the
  `selector` spec and no caller asked for it to change.

- **Prefix rendering.** `ExpandAddressSelector` renders each prefix with
  `netip.Prefix.String`, so a single address materializes as `/32` or
  `/128`. `AddressContains` already handles a prefix against an address, so
  `Matches("ipset:h", "10.9.0.1", "")` settles as before.

## Risks / Trade-offs

- [Existing policies that relied on a bare alias inside an ipset flip from
  resolved to indeterminate] → the control plane rejects that policy, so
  none exists in a tailnet the tool is checking; the `tail-acl` README names
  the accepted forms and the proposal records the change.
- [A deployed policy with `autogroup:internet` inside an ipset reports
  indeterminate through that set until the grammar learns the form] → the
  caveat names the set, `tail-acl lint` will name the member once #373
  closes the lint gap, and #372 resolves it.
- [A pathological IPv6 range expands to many prefixes] → the 65536 cap
  bounds the work and turns the set undecidable rather than slow; a range
  never needs more than 2 × 128 prefixes, so a real policy cannot reach it.
- [The merged covering differs textually from `tail-ipam`'s
  boundary-preserving one] → parity is asserted as address-set equality over
  the `operations` fixture `tail-ipam` already commits, not string equality.
- [`Recognized` now consults the policy for an ipset selector] → it is
  called once per selector per grade in `tailnet-audit`; `ResolveIPSet` is
  bounded and memoized within a call, and the sets are small in practice.
