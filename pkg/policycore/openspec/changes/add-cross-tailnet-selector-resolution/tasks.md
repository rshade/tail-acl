# Tasks: add-cross-tailnet-selector-resolution

## 1. Share the cross-tailnet grammar from alpha

- [x] 1.1 Extract `group://` and `tag://` into named constants in
  `policycore/alpha/nodeshare.go` and refactor `ParseExternalSelector`'s
  scheme switch onto them; verify `go test ./alpha/...` still passes with no
  change to any existing parser test
- [x] 1.2 Add `LooksLikeExternalSelector` reading those same constants, and
  verify a new table-driven test covers a well-formed selector, a malformed
  one that still uses the grammar, a same-tailnet `group:`/`tag:` selector,
  and an unrelated string

## 2. Introduce the policy document container

- [x] 2.1 Add `policycore.Policy` embedding `*tailscale.ACL` with
  `ExternalTailnets alpha.ExternalTailnets` and `HaveExternalTailnets bool`,
  documenting the flag against the `HaveRoles` precedent; verify
  `go build ./...` in `policycore`
- [x] 2.2 Change `Matcher.Policy` to `*Policy` and route every ACL read
  through one nil-safe accessor covering a nil `Matcher.Policy` and a
  container wrapping a nil ACL; verify `go build ./...` and that
  `TestAutogroupResolvable`-style zero-`Matcher` tests still pass
- [x] 2.3 Guard `expandAddressSelectorSeen` against a nil policy document so
  the container's three empty forms are indistinguishable rather than alike
  only in panicking; verify a test covers `ExpandAddressSelector` and
  `IsPublicAddress` against a nil ACL
- [x] 2.4 Keep `SelectorMatches`, `SelectorMatchesTri`, and
  `AnySelectorMatchesTri` taking `*tailscale.ACL`, wrapping internally;
  verify their existing equivalence tests pass unchanged

## 3. Route the cross-tailnet vocabulary through one descriptor

- [x] 3.1 Add an internal `crossTailnetSpecFor` in the shape of
  `autogroupSpecFor`, reporting membership of the vocabulary and carrying
  either the parsed selector or the parse error; verify an internal test
  asserts it recognizes a malformed selector and rejects a same-tailnet one
- [x] 3.2 Add the decision function implementing the design's four-row table
  and verify a table-driven test covers all four rows
- [x] 3.3 Add exported `IsCrossTailnetSelector` and
  `Matcher.KnownExternalTailnetAlias` as views of that descriptor; verify a
  guard test asserts `IsCrossTailnetSelector` agrees with
  `alpha.LooksLikeExternalSelector` over a shared selector corpus, so no
  second list can drift

## 4. Extend the resolvers

- [x] 4.1 Plug the decision function into the resolvability walk beside the
  `autogroup:` branch and after the group walk's fall-through; verify
  `MatchesTri` returns `Unresolvable` for a declared alias and `NoMatch` for
  an undeclared one with the declarations read
- [x] 4.2 Extend `Matcher.Recognized` for the cross-tailnet vocabulary;
  verify tests cover declared, undeclared, malformed, and
  declarations-unread cases
- [x] 4.3 Verify group propagation with new tests: a `Groups` key spelled as
  a cross-tailnet selector stays `Unresolvable`, and a group naming one is
  `Unresolvable` for a non-member but `Matched` for a member
- [x] 4.4 Verify `AnyMatchesTri` names a cross-tailnet selector as the
  reason when nothing matches, and that a later definite match outranks it

## 5. Update consumers and gate the repo

- [x] 5.1 Wrap the ACL at both `tail-acl/internal/aclpolicy` construction
  sites, leaving `HaveExternalTailnets` false; verify
  `cd tail-acl && go test ./...`
- [x] 5.2 Wrap the ACL at all three
  `tailnet-audit/internal/audit/policy/coverage.go` construction sites,
  leaving `HaveExternalTailnets` false; verify
  `cd tailnet-audit && go test ./...`
- [x] 5.3 Update `policycore/README.md` if it documents `Matcher.Policy`'s
  type, and verify `make lint-md`
- [x] 5.4 Run the repo-wide gate set — `make check-tools test build cross
  check-release snapshot-release lint` — and verify every target passes with
  no golden fixture regenerated
