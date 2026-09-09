# Add next-free allocation design

## Context

See proposal.md for motivation and the ipcalc delta specification for the
behavioral contract. `ipcalc.Split` already uses `math/big` and converts
`netip` addresses without imposing CLI or policy dependencies.

## Goals / Non-Goals

**Goals:**

- Provide a reusable, family-agnostic free-child primitive.
- Keep the first-result search proportional to exclusions rather than possible
  child-prefix count.

**Non-Goals:**

- Returning all candidates, parsing CLI flags, or interpreting registry and
  Tailscale data.
- Defining reservation or address-allocation policy.

## Decisions

### Represent addresses as big integer intervals

Convert masked prefixes to half-open `[start, end)` intervals using the same
`math/big` representation as `Split`. Sorting and merging relevant intervals
allows each gap to be rounded up to the requested child boundary; the first
fitting aligned child is the answer. This handles IPv4 and IPv6 without a
separate overflow-prone integer implementation.

### Ignore irrelevant exclusions

Callers often combine inputs from multiple sources. Invalid, other-family, and
non-overlapping exclusions cannot block a pool child and are discarded rather
than making the arithmetic primitive depend on source-specific validation.

### Return a boolean result

The public API returns `(netip.Prefix, bool)`: invalid requests and exhaustion
both have no viable prefix, while callers that need user-facing validation
already know their own input context. This keeps the utility minimal and
matches the issue's proposed API.

## Risks / Trade-offs

- [Large address widths make ordinary integers overflow] → Use `math/big`
  consistently for interval arithmetic.
- [Overlapping exclusions add sorting work] → Merge them first, reducing later
  gap checks and preserving deterministic behavior.
- [A caller needs diagnostics for invalid inputs] → Validate at the caller;
  the primitive intentionally models selection only.

## Migration Plan

This is an additive API. It has no persisted state or runtime migration.
