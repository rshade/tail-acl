# Tasks: add-ipv6-calc-aggregate

## 1. IPv6 aggregation contract

- [x] 1.1 Replace the one-family caller sentence in the `Aggregate` doc
      comment with the mixed-family contract (no cross-family merge or
      cover, IPv4 results first); verify `cd policycore && go vet ./ipcalc`.
- [x] 1.2 Add table-driven cases for adjacent `/49`s, an unordered ULA set
      merging to a `/62`, a `/3` covering narrower descendants, an
      unmergeable IPv6 pair, and a mixed IPv4-and-IPv6 set; verify
      `cd policycore && go test ./ipcalc` passes with the IPv4 cases
      unchanged.

## 2. Specification validation

- [x] 2.1 Validate the change artifacts and implementation together with
      `cd policycore && openspec validate add-ipv6-calc-aggregate && go test ./...`.
