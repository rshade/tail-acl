# IPv6 next-free verification tasks

## 1. Regression and performance coverage

- [x] 1.1 Extend the NextFree table with IPv6 gaps, boundary prefixes,
  mixed-family exclusions, and exhaustion; pass focused tests with a timeout.
- [x] 1.2 Add and run the large-pool benchmark across `/48`, `/64`, and `/128`
  targets, checking results and reporting timing and allocation counts.

## 2. Integration verification

- [x] 2.1 Validate this test-only OpenSpec change and pass repository-wide
  gates with the linked tail-ipam implementation.
