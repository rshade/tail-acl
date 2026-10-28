# Design: add-cross-tailnet-selector-resolution

## Context

See proposal.md — Why. Two constraints shape the approach.

**The autogroup vocabulary is enumerated exactly once.** `autogroupSpecFor`
is a single switch, and `IsRoleAutogroup`, `KnownAutogroup`,
`Matcher.Recognized`, `Matcher.directMatches`, and the resolvability walk are
all views of it, so an autogroup cannot be half-added. The cross-tailnet
vocabulary must be introduced the same way or the second list drifts.

**`externalTailnets` is policy-document data, not control-plane data.** The
user roster is a live fact `Matcher` acquires from the API, which is why
`Roles`/`HaveRoles` sit on `Matcher`. Cross-tailnet relationships are
declared in the policy file itself; the only reason they are not already on
`Matcher.Policy` is that the pinned `tailscale.v2.ACL` does not model the
field, which `alpha`'s migration tripwire test already watches for.

## Goals / Non-Goals

**Goals:**

- One recognition point for the cross-tailnet grammar, shared with the
  parser that already consumes it.
- One decision function producing the whole cross-tailnet verdict, so
  `MatchesTri`, `AnyMatchesTri`, group propagation, and the package-level
  entry points inherit it without individually knowing the vocabulary.
- A policy-document container that can absorb the next hand-modeled field
  without another breaking change.

**Non-Goals:**

- Resolving a cross-tailnet selector when the external tailnet's roster is
  available. The container makes it possible later; nothing consumes it now.
- Parsing `externalTailnets` out of policy HuJSON. Each tool wires its own
  loader in its own change; both consumers leave the flag false here.
- Validating `allowExternalReferencesTo`, or two-policy double opt-in.

## Decisions

### A policy wrapper, not a field pair on `Matcher`

`Policy` embeds `*tailscale.ACL` and carries `ExternalTailnets` plus
`HaveExternalTailnets`. `Matcher.Policy` becomes `*Policy`.

*Why not two more `Matcher` fields?* Because that would place a
policy-document fact beside the live control-plane facts, and the next
hand-modeled field would widen `Matcher` again. Embedding keeps `Groups`,
`Hosts`, and `IPSets` promoted, so the matching walk reads unchanged.

*Why is this affordable?* `policycore` is not enrolled in release-please,
has no tag, and is consumed only through each module's
`replace ... => ../policycore`. There is no pinned version to strand: every
consumer recompiles from source in this commit. AGENTS.md's compatibility
contract covers `tail-acl`'s CLI and output, neither of which changes.

*Shadowing note.* Once the pinned SDK grows a real `ExternalTailnets` field,
`Policy.ExternalTailnets` shadows the promoted one. That is the correct
transitional behavior and `alpha`'s migration tripwire test already fails at
that moment, forcing the deliberate migration it exists to force.

The address helpers (`ExpandAddressSelector`, `IsPublicAddress`,
`AddressContains`) keep taking `*tailscale.ACL`: address expansion has
nothing to do with external tailnets, and widening them would enlarge the
break for no gain. `Matcher` reaches them through a nil-safe accessor so a
zero `Matcher`, a `Matcher` with a nil `Policy`, and a `Policy` wrapping a
nil ACL all behave alike.

*Behaving alike required fixing a latent panic.* `expandAddressSelectorSeen`
read `policy.Hosts` with no nil guard, so all three forms above already
agreed — by panicking. The container makes the third newly constructible
(`&Policy{ExternalTailnets: …}` with the ACL forgotten is a plausible slip),
so the guard is added here: a nil document declares no aliases, and every
selector expands to itself. `IsPublicAddress` routes entirely through
`ExpandAddressSelector`, so the one guard covers both entry points. This is
a deliberate widening of the change beyond issue #274, taken because the
container is what makes the panic easy to reach.

### An undeclared alias is `NoMatch`, but only with the roster read

The decision table is small enough to state whole:

| Selector | Roster read | Verdict |
| --- | --- | --- |
| Parses, alias declared | yes | `Unresolvable` |
| Parses, alias not declared | yes | `NoMatch` |
| Parses | no | `Unresolvable` |
| Malformed | either | `Unresolvable` |

*Why `NoMatch` for an undeclared alias?* An alias is a **local** name — the
key of the local policy's `externalTailnets` map — so an undefined one names
nobody by local evidence alone. The package already reasons this way twice:
the resolvability walk treats an undefined `group:` as settled ("provably
names nobody"), and `settlesRole` lets a tag refute a role autogroup with
certainty. Collapsing this case into `Unresolvable` would make every
cross-tailnet verdict undecidable, which trains callers to ignore the state
and leaves an aliasing typo indistinguishable from a live partner reference.

*Why gate it on `HaveExternalTailnets`?* Without the flag, a nil map from a
caller that never parsed `externalTailnets` is indistinguishable from a
policy that declares none — and both in-repo consumers are in exactly that
position today. Ungated, this change would reintroduce the confident
`NoMatch` it exists to remove.

*Why `Unresolvable` for a malformed selector?* The `://` prefix declares
intent, so `group://partner` is a mistyped cross-tailnet reference, not a
string that happens to name nothing. `autogroupResolvableSeen` already
treats an unrecognized `autogroup:` prefix this way. Reporting `NoMatch`
would let an authoring typo read as "this rule covers nothing".

*Rejected: refuting by query shape.* `settlesRole` can refute a role
autogroup because a tagged device provably has no user owner. No analogous
certainty exists here — an external tailnet's identities are opaque to this
policy, so nothing about a local query's shape refutes a declared external
reference. The general declared-alias case stays `Unresolvable`.

### Recognition lives with the parser; the verdict lives with the matcher

`alpha` gains `LooksLikeExternalSelector`, and `ParseExternalSelector`'s
scheme switch is refactored onto the same two prefix constants, so grammar
recognition and parsing cannot disagree about what a cross-tailnet selector
is. `policycore` adds an internal `crossTailnetSpecFor` in the shape of
`autogroupSpecFor` — it reports whether the selector belongs to the
vocabulary and carries either the parsed selector or the parse error — and
`IsCrossTailnetSelector`, `Matcher.Recognized`, and the resolvability walk
are views of it.

`IsCrossTailnetSelector` reports `true` for a malformed selector too: a
mistyped cross-tailnet reference is still a cross-tailnet reference, and
reporting otherwise would route an authoring typo down the local-selector
path.

The verdict is plugged into `autogroupResolvableSeen` beside the existing
`autogroup:` branch and after the group walk's deliberate fall-through, so
`MatchesTri`, `AnyMatchesTri`, nested-group propagation, and the
package-level entry points inherit it with no per-caller knowledge — and a
`Groups` key that shadows a cross-tailnet selector stays undecidable for the
same conjunction reason a `Groups["autogroup:admin"]` key does.

`Matches` needs no change: a cross-tailnet selector already matches nothing,
and it must keep matching nothing so two-state callers stay conservative.
The wildcard and exact-equality forms keep their existing precedence.

## Risks / Trade-offs

- **The break lands in two modules at once** → both consumers are in this
  repo and use keyed struct literals, so the change is mechanical
  (`Policy: acl` becomes `Policy: &policycore.Policy{ACL: acl}`); the
  repo-wide gate set (`make test build cross lint`) compiles all five CLIs
  against it.
- **Both consumers leave `HaveExternalTailnets` false, so the `NoMatch`
  branch is unreachable in production until their loaders land** → it is
  still reachable, tested, and specified here, and the intermediate state is
  strictly better than today: every cross-tailnet selector reads
  `Unresolvable` instead of a confident `NoMatch`.
- **An `Unresolvable` verdict that used to be `NoMatch` can widen a
  coverage report's "undetermined" set** → that is the intended correction,
  and only for policies that actually use the alpha grammar; a policy with
  no `://` selector is bit-for-bit unaffected.
- **A leading-whitespace selector (`" group://a/b"`) stays unrecognized and
  resolves to `NoMatch`** → accepted and deliberate: every selector form in
  this package is matched on its literal text, and making the cross-tailnet
  grammar alone whitespace-tolerant would be an inconsistency of its own.
  `ParseExternalSelector` still rejects surrounding whitespace for callers
  that parse directly.

## Migration Plan

Single commit. Update `Matcher.Policy`, then the two consumers, then the
tests; `make test` in every module is the gate. Rollback is a revert — no
persisted data, no CLI surface, and no released `policycore` version.
