# Tasks: posture-expression-validation

## 1. Lint rule

- [x] 1.1 Add the `posture-invalid` rule: every expression in every
  `postures` entry runs through `policycore/posture`'s validator, mapping
  unparseable and out-of-vocabulary values to error and unknown attributes
  to warn, with the finding naming posture, expression, and reason at
  `postures[posture:name][index]`. Verify with tests pinning all three
  write-up expressions: `go test -run 'PostureInvalid' ./internal/aclpolicy/`

## 2. Catalog, schema, docs

- [x] 2.1 Add `posture-invalid` to `LintCatalog`, regenerate
  `cmd/tail-acl/testdata/schema.golden.json` and read the diff, and update
  the README lint table from the catalog. Verify with
  `go test ./cmd/tail-acl/ -run TestSchemaSurvivesCobraConversion` and
  `make lint-md` from the repository root

## 3. Authoring validation

- [x] 3.1 Validate every expression in `posture set` before patching:
  error-level diagnostics fail with exit 2 and a byte-identical file
  (tested by before/after byte comparison), warning-level diagnostics print
  to stderr and the edit proceeds, and the `--` terminator behavior is
  unchanged. Verify with
  `go test -run 'PostureSet' ./cmd/tail-acl/`

## 4. Gates

- [x] 4.1 Run `go test ./...` in `tail-acl` and `openspec validate
  posture-expression-validation` in `tail-acl`. Verify both are green
