# Tasks: resolve-ipset-member-forms

## 1. Reachability fixtures

- [x] 1.1 Add the #366 policy as a `reachability_test.go` fixture and one
  test per measured row: `10.1.0.5:80` denied, `10.2.0.5:80`, `10.5.0.4:81`,
  and `10.9.0.1:82` allowed, each naming the matched grant. Verify with
  `go test -run 'IPSet' ./internal/aclpolicy/`
- [x] 1.2 Add the indeterminate fixture: a grant to `ipset:broken`
  (`["host:missing"]`) yields `AccessIndeterminate`, nil `Allowed`, and
  evidence naming the grant. Verify with the same `go test` run
- [x] 1.3 Add a `test` evaluator case beside the other `EvaluateTests`
  cases in `reachability_test.go`: `accept` of `10.2.0.5:80` over the
  trimmed set passes and `deny` of it fails. Verify with
  `go test ./internal/aclpolicy/`

## 2. README

- [x] 2.1 Replace the "`check` and `test` do not yet apply operations…"
  sentence with the forms a local verdict resolves and the indeterminate
  rule for an unmaterializable set, naming `autogroup:internet` inside an
  ipset as a wire-valid member that stays indeterminate until the grammar
  learns it; narrow the "assumes the policy's
  references are valid" paragraph so an undefined selector still matches
  nothing while an undefined reference inside a defined ipset is
  indeterminate. Verify with `make lint-md` from the repo root

## 3. Gates

- [x] 3.1 Run `go build ./... && go test ./... && golangci-lint run ./...` in
  `tail-acl` and confirm the existing check/test goldens are byte-identical
  (`git status --short testdata` shows only the `reachability_policy.hujson`
  member-spelling correction recorded in design.md, no `*.golden.*`)
