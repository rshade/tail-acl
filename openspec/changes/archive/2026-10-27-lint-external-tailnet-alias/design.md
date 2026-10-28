# Design

## Context

`group://` has the prefix `group:`, and `tag://` has the prefix `tag:`.
`undefinedReferenceReason` and the destination-tag check therefore classify
a cross-tailnet selector as a local group or tag. On ACL destinations,
`destinationHost` also splits on the last colon, so `group://alias/name`
becomes the host `group`.

`policycore/alpha` already parses the two forms. `ExternalTailnets` is on
the embedded ACL, so `EvaluateLint` can see it without a new parameter.

## Goals / Non-Goals

**Goals:**

- One error id for an alias this file does not declare.
- A declared alias is not also an undefined local reference.
- The check runs before the `group:` / `tag:` prefix tests and before
  port stripping.

**Non-Goals:**

- Proving the other tailnet's group or tag exists.
- Proving `externalID` names a real tailnet.
- `allowIncomingConnections` (the next lint issue).

## Decisions

### Recognize the form, then stop

`externalSelectorFinding` returns whether the selector is cross-tailnet.
A declared alias returns recognized and no finding, and the caller does
not continue into the local-group or destination-tag checks. An unknown
alias or a parse failure returns the new finding.

### Same id for a parse failure

A value that starts with `group://` or `tag://` and does not parse is still
not a local group. Reporting `undefined-reference` ("not defined in groups")
would repeat the misclassification this change exists to stop.

## Risks / Trade-offs

- `-schema` output grows by one catalog entry. The schema golden is
  regenerated and the diff is that entry.

## Migration Plan

Operators with a typo'd alias start seeing an error. A policy that already
declares the alias is unchanged.

## Open Questions

None.
