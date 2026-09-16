# Tasks: resolve-ipset-member-forms

## 1. Resolver

- [x] 1.1 Add `ResolveIPSet(name, policy) ([]netip.Prefix, error)` in a new
  `policycore/ipsetresolve.go`: parse each member with `ParseIPSetMember`,
  apply operations in order through `netipx.IPSetBuilder`, resolve `host:`
  by one `Hosts` lookup that must yield a literal address or prefix, recurse
  `ipset:` with a path-scoped
  cycle guard, a per-call memo, a 128-level depth limit, and a 65536-prefix
  cap; every failure returns an error naming the set and member position.
  Verify with unit tests for each `ipset` delta scenario, including the
  diamond and the cycle
- [x] 1.2 Add `policycore/testdata/operations.policy.hujson` copied byte for
  byte from `tail-ipam/internal/policycheck/testdata/`, and a parity test
  asserting each set's address space equals the space `tail-ipam`'s
  `operations.report.golden.json` records. Verify with `go test -run
  Parity ./...`
- [x] 1.3 Promote `go4.org/netipx` to a direct requirement in `go.mod` and
  verify `go mod tidy` leaves `go.sum` unchanged

## 2. Expansion and decidability

- [x] 2.1 Route the `IPSets` branch of `expandAddressSelectorSeen` through
  `ResolveIPSet`, rendering prefixes as strings and expanding to nothing on
  error; keep the `Hosts` branch as is. Verify the existing
  `TestExpandAddressSelector*` tests pass and add cases for the four
  `selector` delta scenarios
- [x] 2.2 Make `selectorResolvableSeen` and `Recognized` report an
  `IPSets` selector whose `ResolveIPSet` errors as undecidable. Verify with
  tests for the three `resolvable` delta scenarios, including the group
  nesting case and the empty-set-is-decidable case
- [x] 2.3 Verify `Matches`/`MatchesTri` for a bare alias member (`["gw"]`)
  report no match and `Unresolvable`, pinning the deliberate grammar change

## 3. Documentation and gates

- [x] 3.1 Update `docs/public-api.md`: document `ResolveIPSet`, replace the
  "does not yet apply this grammar" paragraph, and extend the resolution
  boundaries note. Verify with `make lint-md` from the repo root
- [x] 3.2 Run `go build ./... && go test ./... && golangci-lint run ./...`
  in `policycore`, then the repo-wide gates (`make check-tools test build
  cross check-release snapshot-release lint`) because every module compiles
  this package through a local `replace`
