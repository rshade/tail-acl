# IPv6 next-free verification design

## Context

The `ipcalc` spec already requires family-safe gap search. Its implementation
sorts and merges exclusion intervals using `math/big`; no code change is
planned. See `proposal.md` for the coverage gap.

## Goals / Non-Goals

Verify correctness across IPv6 widths and demonstrate that a large occupied
range is skipped directly. Do not change the algorithm or introduce timing
thresholds into unit tests.

## Decisions

- Extend the existing table with `/0`, `/32`, `/127`, and `/128` cases,
  unaligned exclusions, full exhaustion, and the maximum address.
- Benchmark a fixed `/32` pool with a `/33` exclusion and target widths
  `/48`, `/64`, `/128`. Keep fixture parsing outside the timed loop, report
  allocations, and check returned prefixes.
- Use ordinary exact-result tests instead of wall-clock assertions; benchmark
  measurements provide performance evidence without flaky hardware limits.

## Risks / Trade-offs

- A future enumeration regression could stall a large-gap test → use a
  bounded timeout for focused verification and retain benchmark evidence.
- No library behavior changes → skip spec deltas explicitly and preserve
  the existing authoritative requirements.
