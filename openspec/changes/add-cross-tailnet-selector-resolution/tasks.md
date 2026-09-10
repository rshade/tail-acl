# Tasks: add-cross-tailnet-selector-resolution

## 1. Adopt the policy container

- [x] 1.1 Wrap the ACL in `policycore.Policy` at both `internal/aclpolicy`
  construction sites, leaving `HaveExternalTailnets` false; verify
  `go build ./...` and `go test ./...` pass with no golden fixture changed

## 2. Verify the verdict contract

- [x] 2.1 Verify `check` reports `indeterminate` and exits 10 for a policy
  whose only covering ACL uses a cross-tailnet source selector, and that the
  JSON envelope omits `allowed`
- [x] 2.2 Verify a policy using no cross-tailnet selector is unchanged, by
  running the module's existing golden and integration tests untouched
