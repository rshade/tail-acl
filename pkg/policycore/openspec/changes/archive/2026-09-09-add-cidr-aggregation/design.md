# CIDR Aggregation Design

## Context

`ipcalc` already owns IPv4 prefix arithmetic and its callers need a shared,
deterministic summarization primitive. See proposal.md for motivation and the
delta spec for its observable contract.

## Goals / Non-Goals

**Goals:**

- Produce the exact minimal cover for valid IPv4 input without enumeration of
  individual addresses.
- Keep the primitive independent of CLI parsing and registry state.

**Non-Goals:**

- IPv6 aggregation, registry discovery, or route-policy interpretation.
- Changing `addrspace` overlap APIs.

## Decisions

- Normalize and sort prefix network ranges before reducing them, so duplicate
  and covered prefixes disappear before sibling merges. This provides stable
  output independent of caller order.
- Merge only equal-length siblings into their shared parent, repeating through
  the ordered collection until no parent is newly complete. This preserves
  exact address coverage without enumerating hosts. A range-set implementation
  was considered but is unnecessary for fixed-width IPv4 CIDRs.

## Risks / Trade-offs

- [Unexpected non-IPv4 library input] → The CLI validates input before calling
  the primitive; tests document the supported valid-IPv4 domain.
- [Accidental non-minimal output] → Include sibling, overlap, and multi-level
  merge test cases.

## Migration Plan

This is an additive library API with no persisted state or migration. Callers
can adopt it independently.
