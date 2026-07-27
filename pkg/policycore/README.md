# policycore

Selector resolution for Tailscale policy files, shared by `tail-acl` and
`tailnet-audit`.

Both tools need to answer one question identically: *does this policy selector
name this thing?* Two tools in the same repo disagreeing about one policy is
worse than duplicated code, so the logic lives here rather than in each tool.

## Scope

In scope — resolving a selector to the values it names:

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
- `via` routing and posture evaluation
- Policy parsing, merging, and upload

## Usage

A `Matcher` carries the policy plus the live tailnet facts the policy document
cannot supply:

```go
matcher := policycore.Matcher{Policy: policy}
matched := matcher.AnyMatches(rule.Source, "tag:web", "")
```

A caller that has read the tailnet's user roster supplies it, which is what lets
the role autogroups resolve:

```go
matcher := policycore.Matcher{Policy: policy, Roles: roles, HaveRoles: true}
```

A caller with no tailnet access uses the roster-blind entry point instead:

```go
matched := policycore.SelectorMatches("group:eng", "ada@example.com", policy, "")
```

## Module layout

This is a library module with no binary. It depends only on the Tailscale v2
API client and the standard library.
