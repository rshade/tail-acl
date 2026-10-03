# Tasks: lint-posture-references

## 1. Reference resolution

- [x] 1.1 Flag a `srcPosture` (grant or ACL entry) or `defaultSrcPosture`
  entry naming a posture missing from `postures` as `undefined-reference`
  (error), resolving names with `NormalizePostureName`. Verify with tests
  for every `lint` delta scenario: the write-up probe yields exactly one
  error for `posture:missing` — `go test -run 'LintPosture' ./internal/aclpolicy/`

## 2. Unused postures

- [x] 2.1 Add the `unused-posture` info rule: a posture no `srcPosture` or
  `defaultSrcPosture` references, with default references counting. Replace
  `TestEvaluateLintDoesNotFlagSrcPostureOrPostures` with positive tests:
  the probe's `posture:unused` yields one info finding, and a posture
  referenced only from `defaultSrcPosture` is not reported. Verify with
  `go test -run 'UnusedPosture|LintPosture' ./internal/aclpolicy/`

## 3. Catalog, schema, docs

- [x] 3.1 Add `unused-posture` to `LintCatalog`, regenerate
  `cmd/tail-acl/testdata/schema.golden.json` (`go test ./... -update`, read
  the diff), and update the README lint table from the catalog. Verify with
  `go test ./cmd/tail-acl/`
- [x] 3.2 Rewrite the posture-authoring paragraph (README.md:607-610) so the
  dangling-reference sentence is true and names `undefined-reference`.
  Verify with `make lint-md` from the repo root
- [x] 3.3 Run `go test ./...` in `tail-acl` and `openspec validate
  lint-posture-references` in `tail-acl`. Verify both are green
