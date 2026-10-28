# Tasks: effective-src-posture

## 1. Helper

- [x] 1.1 Add `policycore/posture.go` with
  `EffectiveSrcPosture(own, fallback []string) ([]string, bool)` implementing
  replacement semantics and origin reporting. Verify with table tests
  covering every `posture` delta scenario: `go test -run EffectiveSrcPosture ./...`

## 2. Gates

- [x] 2.1 Run `go test ./...` in `policycore` and `openspec validate` in
  `policycore`. Verify both are green
