# CIDR Aggregation Tasks

## 1. IPv4 aggregation primitive

- [x] 1.1 Add the `ipcalc` aggregation API that normalizes, orders, and reduces valid IPv4 prefixes;
  verify sibling, overlap, and multi-level cases with unit tests.
- [x] 1.2 Verify the policycore module with `go test ./...` after aggregate tests cover deterministic
  output and non-mergeable prefixes.
