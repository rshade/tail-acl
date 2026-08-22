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

## Module layout

This is a library module with no binary. Production `addrspace` code uses only
the standard library. Its Tier-2 provenance test imports the pinned
`tailscale.com/net/tsaddr` package to cross-validate the owned 4via6 decoder;
no production package imports the full `tailscale.com` module.

## Documentation

This README covers the resolution semantics. For the exported functions,
signatures, and helper inventory, see the
[public API reference](./docs/public-api.md).
