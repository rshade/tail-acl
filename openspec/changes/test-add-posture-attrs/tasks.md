# Tasks: test-add-posture-attrs

## 1. Authoring

- [x] 1.1 Add `--src-posture-attr KEY=VALUE` (repeatable) to `test add`,
  writing the typed attributes into a new entry's `srcPostureAttrs` via the
  shared `ParsePostureAttrs` helper. Verify with
  `go test -run 'TestTestAddWithPostureAttrs' ./cmd/tail-acl/`

## 2. Merge semantics

- [x] 2.1 Identify a posture test by source AND attributes: an add carrying
  attributes merges only on a deep-equal `srcPostureAttrs`, forks on any
  difference, and a flag-less edit matches only entries with no key or an
  empty one. Replace the never-a-merge-target rule and update its two pinned
  tests to the new semantics. Verify with
  `go test -run 'PostureAttrs|EmptyPostureAttrs|FlaglessAdd' ./internal/aclpolicy/`

## 3. Removal and key check

- [x] 3.1 `test remove --src-posture-attr` targets an exact attribute-map
  match under the existing renumbering rules; no exact match is no_changes.
  Verify with `go test -run 'TestTestRemoveWithPostureAttrs' ./cmd/tail-acl/`
- [x] 3.2 Warn on stderr for unknown `node:`/`ip:` and namespace-less keys
  (edit proceeds; `custom:` never warns), and reject a repeated key with
  exit 2 and a byte-identical file. Verify with
  `go test -run 'PostureAttrWarnings|DuplicatePostureAttr' ./cmd/tail-acl/`

## 4. Docs and gates

- [x] 4.1 Rewrite the README posture-qualified-entries bullet and the
  command table rows, document the value typing by reference to `check`'s
  rule, and regenerate the schema golden (usage strings), reading the diff.
  Verify with `go test ./cmd/tail-acl/ -run TestSchemaSurvivesCobraConversion`
  and `make lint-md` from the repository root
- [x] 4.2 Run `go test ./...` and `golangci-lint run` in `tail-acl`, and
  `openspec validate test-add-posture-attrs`. Verify all are green
- [x] 4.3 Dogfood against a copy of the reference policy in /tmp: remove
  tests[2] by exact attrs, rebuild it with the write-up command, re-run for
  no_changes, fork with `ip:country=IR`, and run the suite green. Verify
  with the fresh binary's outputs
