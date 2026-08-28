# policycore

Selector resolution, address-space primitives, and the repository-wide output
sanitization contract, shared by the tool modules.

Both tools need to answer one question identically: *does this policy selector
name this thing?* Two tools in the same repo disagreeing about one policy is
worse than duplicated code, so the logic lives here rather than in each tool.

## Scope

The `sanitize` subpackage owns level parsing, environment-over-flag precedence,
HMAC placeholder allocation, exact known-value replacement in prose, strict
timestamp quantization, envelope metadata, and reflection-guard support. It
does not know any tool's report shape: each binary rebuilds its own output types
from zero at the render boundary so a newly added field cannot pass through
without an explicit decision.

The `addrspace` subpackage compares route CIDRs and recognizes Tailscale 4via6
prefixes, including extracting their embedded site IDs. It knows neither static
policy shape nor live device state, and it does not decide whether an overlap or
repeated site ID is intentional; callers own those classifications.

The `hujsonedit` subpackage applies schema-agnostic, comment-preserving RFC
6902 edits to HuJSON documents. It carries no knowledge of any particular
document's fields; `tail-acl` and `tail-ipam` both build their typed edits on
it.

The `alpha` subpackage is the convention for hand-modeling a Tailscale
feature that is alpha or unreleased in the pinned SDK — see
[Alpha feature modeling](#alpha-feature-modeling) below. It carries no
knowledge of any particular alpha feature's types.

For selector matching, the scope is resolving a selector to the values it
names:

- `*` and the full autogroup vocabulary, split into role autogroups (resolved
  from the tailnet's user roster) and autogroups resolved from the policy
  document alone — `autogroupSpecFor` in `autogroup.go` is the single,
  authoritative enumeration; this README does not restate it
- `tag:` and user selectors
- `group:` expansion, including nesting, with a cycle guard
- `Hosts` and `IPSets` expansion, with a cycle guard
- CIDR and address containment

Out of scope — kept in `tail-acl`:

- Port and protocol evaluation
- `via` routing behavior and posture evaluation
- Policy parsing, merging, and upload

The one shared policy-shape predicate is `ContainsLiteralWildcard`. Both
`tail-acl` and `tailnet-audit` use it to keep the ownership boundary between a
static literal-wildcard advisory and a destination that becomes broad only
after resolving it against the live fleet. It recognizes only a port-stripped
literal `*`; it deliberately does not classify any autogroup as a wildcard.

## Usage

A `Matcher` carries the policy plus the live tailnet facts the policy document
cannot supply:

```go
matcher := policycore.Matcher{Policy: policy}
matched := matcher.AnyMatches(rule.Source, "tag:web", "")
```

A caller that has read the tailnet's user roster supplies it, which is what lets
the role autogroups resolve. `HaveRoles` is an assertion that the roster is
complete and authoritative; leave it false after a failed, partial, or
truncated read:

```go
matcher := policycore.Matcher{Policy: policy, Roles: roles, HaveRoles: true}
```

A matcher can preserve the difference between a definite non-match and missing
live state:

```go
match := matcher.MatchesTri("autogroup:admin", "ada@example.com", "")
```

For a role autogroup such as `autogroup:admin`, roster availability and query
shape determine the three-state result:

| `HaveRoles` | Query shape | Roster result | Verdict |
| --- | --- | --- | --- |
| `false` | tag | — | `NoMatch` |
| `false` | user or bare device/CIDR | — | `Unresolvable` |
| `true` | tag | — | `NoMatch` |
| `true` | user | matching role | `Matched` |
| `true` | user | another role | `NoMatch` |
| `true` | user | absent | `NoMatch` |
| `true` | bare device/CIDR | — | `Unresolvable` |

A complete roster maps logins to roles. It makes an absent user a definite
non-match, but it cannot settle a bare device address because it does not map
devices to owners.

Three-state resolution follows nested groups. A group is decidable only when
every member is decidable against the query; one nested undecidable autogroup
makes a non-matching group `Unresolvable`. A definite match by any member still
settles the group as `Matched`. Undefined groups remain definite non-matches,
and group cycles terminate without being treated as missing live state.

Membership is keyed on the selector itself, not on the `group:` prefix, so a
`groups` entry the control plane would reject resolves the same way here as one
it accepts. Matching and resolvability read that one lookup, which is what keeps
a group the matcher expands from being reported as settled.

A caller with no tailnet access uses the roster-blind entry point instead:

```go
matched := policycore.SelectorMatches("group:eng", "ada@example.com", policy, "")
```

## Alpha feature modeling

`policycore/alpha` is the shared convention for hand-modeling a Tailscale
feature that is alpha or unreleased in the pinned
`tailscale.com/client/tailscale/v2` SDK, so a tool in this repo can pick up an
alpha feature early instead of waiting for the SDK to catch up. It is
scaffolding only — no specific alpha feature's types live here; each
feature's hand-modeled types live with the tool that needs them (or in a new
`policycore/` subpackage, if more than one tool needs the same types resolved
identically, following the precedent above).

Adding an alpha-backed feature:

1. Hand-model the feature's types where the tool that needs them lives, or in
   a new `policycore/` subpackage if it must be shared.
2. Add it to the slice returned by `alpha.RepositoryFeatures()` in
   `policycore/alpha/alpha.go`. That function is the canonical repository-wide
   inventory naming every hand-modeled alpha feature, its doc source, when this
   repo started modeling it, and where it sits in Tailscale's own release
   pipeline:

   ```go
   func RepositoryFeatures() []Feature {
       return []Feature{
           {
               Name:        "declarative-node-sharing",
               DocURL:      "https://tailscale.com/kb/example",
               ModeledDate: time.Date(2026, time.September, 1, 0, 0, 0, 0, time.UTC),
               Stage:       StageAlpha,
           },
       }
   }
   ```

   `alpha.NewRegistry()` instead returns an empty, caller-owned registry for
   validation and lookup. Calling `Register` on that value does not update the
   repository inventory.

3. Give the feature its own migration tripwire — typically a test that fails
   once the pinned SDK adds real support for it, forcing a conscious decision
   to migrate off the hand-modeled types instead of letting them silently
   diverge from the now-real SDK types. `alpha.RepositoryFeatures()` exposes
   the feature and its `Stage`; it does not enforce that feature's tripwire
   itself, so updating `Stage` as the feature moves through the pipeline is on
   the contributor doing the migration.
4. Cite alpha-sourced data with `alpha.AlphaHint` as the source-provenance
   confidence, not `"hint"`. `"alpha-hint"` is an allowed `SourceRef`
   confidence value in `tailscale-doctor` and `tailnet-audit` (AGENTS.md AX
   convention 13): `"hint"` is editorial evidence verified at test time to
   resolve in a *stable pinned* module, while `AlphaHint` is editorial evidence
   against a surface Tailscale itself calls unstable — categorically weaker.

## Module layout

This is a library module with no binary. Production `addrspace` code uses only
the standard library. Its Tier-2 provenance test imports the pinned
`tailscale.com/net/tsaddr` package to cross-validate the owned 4via6 decoder;
no production package imports the full `tailscale.com` module.

## Documentation

This README covers the resolution semantics. For the exported functions,
signatures, and helper inventory, see the
[public API reference](./docs/public-api.md).
