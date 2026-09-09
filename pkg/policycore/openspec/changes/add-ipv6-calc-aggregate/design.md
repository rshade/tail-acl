# Design: add-ipv6-calc-aggregate

## Context

See proposal.md. `Aggregate` sorts by address then prefix length, skips
prefixes covered by the last kept prefix, and merges trailing siblings. Every
primitive it uses is already family-aware: IPv4 addresses sort before IPv6,
containment is false across families, and the sibling check compares family
before width.

## Goals / Non-Goals

**Goals:**

- State the IPv6 and mixed-family contract that the implementation already
  satisfies, and prove it with tests.

**Non-Goals:**

- Changing the algorithm, its complexity, or its signature.
- Adding family filtering or per-family entry points.

## Decisions

### Specify mixed-family input instead of forbidding it

The one-family caller contract in the doc comment was a conservative default
from the IPv4-only change, not a limitation of the code. Because the sort
places IPv4 first and neither containment nor sibling detection crosses
families, mixed input already produces the IPv4 cover followed by the IPv6
cover. Documenting that is cheaper and more useful than adding a rejection
path, and it lets `tail-ipam` accept a dual-stack argument list without
splitting it first.

### Prove behavior with tests rather than code

Adding IPv6 and mixed cases to the existing table keeps one assertion style
and shows the IPv4 cases unchanged, which is the evidence the tail-ipam
change relies on.

## Risks / Trade-offs

- [A future refactor breaks the cross-family invariant silently] → the mixed
  family test case pins ordering and non-merging.
- [Wide prefixes expose an edge in parent derivation] → cover a `/3` that
  absorbs narrower descendants; the `/0` guard in sibling detection stays.
