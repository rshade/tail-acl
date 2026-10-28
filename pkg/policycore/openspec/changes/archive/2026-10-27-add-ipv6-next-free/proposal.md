# Verify IPv6 next-free allocation

## Why

Issue #257 exposes the existing family-agnostic `ipcalc.NextFree` primitive
through tail-ipam's IPv6 CLI. Its current tests exercise only a tiny IPv6
pool; larger gaps and address-space boundaries need regression coverage.

## What Changes

- Add table-driven IPv6 gap, alignment, exhaustion, mixed-family, and
  `/127`/`/128` boundary cases.
- Benchmark `/32` pools with `/48`, `/64`, and `/128` targets after excluding
  half the pool, demonstrating that candidate count does not drive the search.
- Preserve the existing algorithm and public API.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

None. This is test-only verification of the existing `ipcalc` requirements;
`skip_specs: true` records that no spec-level behavior changes here.

## Impact

Only `ipcalc/nextfree_test.go` changes. The matching tail-ipam change owns the
CLI capability extension. Run repository-wide gates because the shared
library is consumed through local module replacements.
