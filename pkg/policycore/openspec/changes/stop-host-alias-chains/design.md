# Design

## Context

`expandAddressSelectorSeen` treats `policy.Hosts[selector]` as another
selector and recurses. The control plane does not. `ParseAddr` rejects a
host name, a tag, and any other non-address. `ResolveIPSet` already requires
a `host:` target's `Hosts` value to be a literal and does not follow a chain.
`MatchesTri` only reports `Unresolvable` when `selectorResolvable` is false.
A non-literal host currently falls through as a settled non-match.

## Goals / Non-Goals

**Goals:**

- One `Hosts` lookup. Return the value. Do not follow it.
- A literal address or prefix is that literal, not a second host key.
- A non-literal host is unmaterializable for `Recognized` and
  `selectorResolvable`, same shape as `ipsetMaterializes`.
- Keep the cycle guard. It no longer has a host chain to walk.

**Non-Goals:**

- Changing ipset member grammar or `ResolveIPSet`.
- Authoring or lint. Those are the `tail-acl` change of this slug.
- Removing the cycle guard.

## Decisions

1. **Do not recurse on a host value.** Both the literal and the non-literal
   cases return `[]string{value}`. Recursing on a literal would look that
   string up as a host name, which the control plane does not do. Recursing
   on a non-literal is the bug.
2. **Literal means `netip.ParsePrefix` or `netip.ParseAddr` succeeds.** That
   is the same test `lint` already uses for `host-not-address`, including a
   zoned address such as `fe80::1%eth0`.
3. **Unmaterializable, not `NoMatch`.** `hostMaterializes` sits beside
   `ipsetMaterializes` in `selectorResolvableSeen` and `Recognized`. A group
   member that is such a host stays undecidable unless another member
   matches. A literal host stays decidable, including a confident `NoMatch`.

## Risks / Trade-offs

- **BREAKING** for any caller that expanded `alias -> web -> CIDR`. The
  result is now `["web"]`. That caller was agreeing with a policy
  `validate` rejects.
- A host whose value is itself an ipset name used to expand the set. It now
  returns the name. The control plane rejects that value too.

## Migration Plan

No data migration. Policies with alias chains already fail `validate`.
Callers should read the host value as written and treat a non-literal as
indeterminate.

## Open Questions

None.
