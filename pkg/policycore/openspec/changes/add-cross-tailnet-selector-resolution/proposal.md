# Proposal: add-cross-tailnet-selector-resolution

## Why

A cross-tailnet selector — `group://<alias>/<name>` or `tag://<alias>/<name>`
— names members of *another* tailnet, whose roster this tailnet's policy
document cannot supply. `Matcher` does not recognize the grammar today, so
such a selector falls through direct matching, group expansion, and address
expansion to a `NoMatch`, and `Recognized` reports it as understood because
it carries no `autogroup:` prefix. A coverage or reachability verdict
therefore claims confidently that access is denied when the truth is "cannot
be determined from this tailnet's policy alone" — the one wrong answer
`Match` exists to prevent.

`policycore/alpha` already models the grammar (`ParseExternalSelector`) and
the relationship data (`ExternalTailnets`); nothing routes them into the
matcher.

This is the `policycore` part of a change spanning three modules under the
shared slug `add-cross-tailnet-selector-resolution`. Both consumers change
user-visible output as a result, so each carries its own change:
`tail-acl/openspec/changes/add-cross-tailnet-selector-resolution/` (a
cross-tailnet selector joins the causes of an `indeterminate` verdict) and
`tailnet-audit/openspec/changes/add-cross-tailnet-selector-resolution/` (it
joins the selectors that caveat coverage).

## What Changes

- **BREAKING**: `Matcher.Policy` changes from `*tailscale.ACL` to a new
  `*policycore.Policy` wrapper embedding `*tailscale.ACL` alongside the
  policy fields the pinned SDK does not model.
- `Policy` carries `ExternalTailnets` plus `HaveExternalTailnets`, which
  distinguishes "the policy declares no external tailnets" from "the caller
  never parsed the field" — the same distinction `HaveRoles` draws for the
  user roster.
- The tri-state resolvers report `Unresolvable` for a cross-tailnet selector
  whose alias is declared, and for any cross-tailnet selector when the
  external-tailnet roster was not read or the selector is malformed.
- A cross-tailnet selector naming an alias the policy provably does not
  declare resolves to `NoMatch`, but only when the roster was read — an
  undeclared alias is a locally decidable authoring error, exactly as an
  undefined `group:` provably names nobody.
- `alpha` gains `LooksLikeExternalSelector`, the grammar-recognition view of
  the same prefixes `ParseExternalSelector` consumes, so recognition and
  parsing cannot drift apart.
- `policycore` gains `IsCrossTailnetSelector` and
  `Matcher.KnownExternalTailnetAlias`, both routed through one internal
  descriptor in the shape of `autogroupSpecFor`.

## Capabilities

### New Capabilities

<!-- None. -->

### Modified Capabilities

- `alpha`: add grammar recognition alongside cross-tailnet selector parsing.
- `selector`: `Matcher` holds a policy wrapper rather than a bare SDK ACL,
  and cross-tailnet selectors are recognized as their own vocabulary.
- `resolvable`: `MatchesTri`, `AutogroupResolvable`, and `Recognized` extend
  to the cross-tailnet vocabulary and its decision table.

## Impact

- `policycore/selector.go`, `resolvable.go`, `autogroup.go` and a new
  `crosstailnet.go`/`policy.go` pair.
- `policycore/alpha/nodeshare.go` shares its scheme prefixes.
- `tail-acl/internal/aclpolicy/{check,test}.go` and
  `tailnet-audit/internal/audit/policy/coverage.go` wrap their ACL when
  constructing a `Matcher`; both keep `HaveExternalTailnets` false, so every
  cross-tailnet selector reads `Unresolvable` until each tool wires its own
  HuJSON parsing in a separate change.
- No CLI surface, flag, or machine-readable output changes in *this* module.
  Both consumers do change user-visible output, which their own changes under
  the shared slug specify: `tail-acl check` moves from exit 1 / `"access":
  "deny"` to exit 10 / `"access": "indeterminate"` for a policy using the
  grammar.
- `policycore` is not enrolled in release-please and carries no tag; every
  consumer compiles it from source through a local `replace`, so the
  breaking Go change strands no released version.
