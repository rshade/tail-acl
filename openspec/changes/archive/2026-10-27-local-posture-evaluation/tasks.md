# Tasks: local-posture-evaluation

## 1. Evaluator

- [x] 1.1 Add the explicit-attribute evaluation entry point to
  `policycore/posture` (`Attrs{Map, Complete}`, `EvaluatePosture` with
  per-expression verdicts, server semantics under completeness, the
  conservative partial-mode fold, and unevaluable version comparisons),
  reproducing the reference policy's truth table. Verify with
  `go test -run 'EvaluatePosture' ./posture/` in `policycore`
- [x] 1.2 Verify `tailnet-audit` keeps zero golden diffs. Verify with
  `go test ./...` in `tailnet-audit`

## 2. test

- [x] 2.1 Delete the whole-file `srcPostureAttrs` refusal and evaluate each
  test's gate against its attribute map (presence-based, complete); replace
  the fixed `postureGate` strings with evaluation when attributes are
  supplied, keeping the legacy wording when they are not. Verify with
  `go test -run 'PostureGate|PostureReference|MixedPosture|EmptySrcPostureAttrs' ./internal/aclpolicy/`
- [x] 2.2 List an unparseable posture expression in the policy-scoped
  `skipped` array via `scanRules`. Verify with
  `go test -run 'PostureGateUnevaluable' ./internal/aclpolicy/`
- [x] 2.3 Seed the reference, flipped-expectation, mixed, and empty-attrs
  fixtures and regenerate the report golden, reading every line. Verify with
  `go test -run 'Golden' ./internal/aclpolicy/`

## 3. check

- [x] 3.1 Add `--posture-attr` (repeatable) and `--posture-attrs-complete`
  with the shared `KEY=VALUE` typing helper, and pin both acceptance probes:
  complete KP set → exit 1, same without the flag → exit 10. Verify with
  `go test -run 'CheckPostureAttr' ./cmd/tail-acl/`

## 4. Docs and gates

- [x] 4.1 Rewrite the README `test` posture paragraph, the safety-boundary
  section, and the check flag docs; fix the stale posture-qualified-entry
  bullet. Verify with `make lint-md` from the repository root
- [x] 4.2 Run `go test ./...` and `golangci-lint run` in `tail-acl`, and
  `openspec validate local-posture-evaluation`. Verify all are green
- [x] 4.3 Dogfood with a freshly built binary: the reference policy's
  `tail-acl test` passes all seven with exit 0; the two check probes exit 1
  and 10. Verify with `go build -o /tmp/tail-acl-f04 ./cmd/tail-acl` and the
  three probe commands
