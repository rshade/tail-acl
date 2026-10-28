# Design

## Context

`ipset add` already parses members with `policycore.ParseIPSetMember` and
walks cycles with `ipsetReferencePath`. Hand-written policies never enter
that path.

## Goals / Non-Goals

**Goals:**

- One error per invalid member, missing reference, or bad host value.
- One error per cycle, reported from the lexicographically smallest set.
- Leave `ipset-mixed-operations` on its current classifier.

**Non-Goals:**

- Resolving members to prefixes.
- Accepting `autogroup:internet` as a member.
- Following `hosts` alias chains.

## Decisions

Reference and cycle checks call `ParseIPSetMember` and `ipsetReferencePath`.
A cycle is reported once, from the smallest set name on the path. A host
value is an address or a prefix when `netip` parses it. Each new id is an
error, so `lint` exits non-zero.

## Risks / Trade-offs

- `-schema` gains four catalog objects.

## Migration Plan

Existing policies that `validate` would reject now fail `lint` first.

## Open Questions

None.
