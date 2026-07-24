# policycore

Selector resolution for Tailscale policy files, shared by `tail-acl` and
`tailnet-audit`.

Both tools need to answer one question identically: *does this policy selector
name this thing?* Two tools in the same repo disagreeing about one policy is
worse than duplicated code, so the logic lives here rather than in each tool.

## Scope

In scope — resolving a selector to the values it names:

- `*`, `autogroup:self`, `autogroup:member`, `autogroup:internet`
- `tag:` and user selectors
- `group:` expansion, including nesting, with a cycle guard
- `Hosts` and `IPSets` expansion, with a cycle guard
- CIDR and address containment

Out of scope — kept in `tail-acl`:

- Port and protocol evaluation
- `via` routing and posture evaluation
- Policy parsing, merging, and upload

## Usage

```go
matched := policycore.AnySelectorMatches(rule.Source, "tag:web", policy, "")
```

## Module layout

This is a library module with no binary. It depends only on the Tailscale v2
API client and the standard library.
