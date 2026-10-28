# Design

## Context

`allowIncomingConnections` lives on the alias, not on the grant. Issue 278
already reports an alias this file does not declare. This check
runs only after that alias is present, so the two findings do not stack
on a typo.

## Goals / Non-Goals

**Goals:**

- Warn on grant `src` and `dst` when the declared alias's flag is not true.
- Say why: the grant names the alias, and the alias does not allow
  incoming connections.

**Non-Goals:**

- ACL, SSH, and auto-approver positions. The issue scopes the check to
  grants.
- The other tailnet's `allowExternalReferencesTo`.

## Decisions

A zero `AllowIncomingConnections` is the omitted and the explicit false
case. The SDK field is a bool, so those two documents decode the same.

Unknown and unparsed selectors are skipped. The alias-unknown check
already owns them.

## Risks / Trade-offs

- `-schema` gains one warning. The schema golden diff is that entry.

## Migration Plan

Policies that already set the flag true are unchanged.

## Open Questions

None.
