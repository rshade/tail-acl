# Tasks: effective-src-posture

## 1. Evaluator

- [x] 1.1 Gate grants and ACL entries on
  `policycore.EffectiveSrcPosture(rule, policy.DefaultSourcePosture)` in
  `internal/aclpolicy/test.go`, and give `postureGate` origin-aware wording
  (`uses unsupported srcPosture (from defaultSrcPosture)` when the gate came
  from the default). Verify with unit tests: own posture ignores the
  default, no default keeps current verdicts — `go test -run 'PostureGate|Reachability' ./internal/aclpolicy/`

## 2. Fixtures

- [x] 2.1 Add golden fixtures seeded from the Features/01 probes (grant form
  and `acls` form, both confirmed against the server on 2026-10-02: the
  grant form drops, the `acls` deny assertion holds). Each fixture records
  the server verdict and date in a provenance comment in the policy file.
  Verify `tail-acl test` and `check` on both probes report indeterminate
  (exit 10), never reachable/PASS
- [x] 2.2 Regenerate any affected goldens with `go test ./... -update` and
  read every changed fixture; only default-origin gate text may change.
  Verify with `git status --short internal/aclpolicy/testdata`

## 3. Documentation and gates

- [x] 3.1 Update the README posture section to state the default gates
  locally. Verify with `make lint-md` from the repo root
- [x] 3.2 Run `go test ./...` in `tail-acl` and `openspec validate` in
  `tail-acl`. Verify both are green
