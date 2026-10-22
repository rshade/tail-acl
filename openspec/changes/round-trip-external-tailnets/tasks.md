# Tasks

## 1. Reference walks

- [x] 1.1 Count `externalTailnets[*].allowExternalReferencesTo` in
  `collectReferences` and name `externalTailnets` in the unused-definition
  decision trace.
- [x] 1.2 Count the same selectors in `DefinitionReferences`, with locator
  `externalTailnets[<alias>].allowExternalReferencesTo[<index>]`.

## 2. Tests

- [x] 2.1 A group referenced only from the allow-list is not `unused-group`,
  and `RemoveDefinition` refuses it without `--force`.
- [x] 2.2 Load populates `ExternalTailnets`, and a comment inside that object
  survives an unrelated `WritePatch`.
- [x] 2.3 Regenerate `lint_report.golden.json` with
  `go test ./internal/aclpolicy -update` and read the diff.

## 3. Verify

- [x] 3.1 `openspec validate round-trip-external-tailnets` from `tail-acl`.
- [x] 3.2 `go test ./...` and `golangci-lint run ./...` in `tail-acl`,
  cross-build `tail-acl` for linux, windows, and darwin, and `make lint-md`.
  Repo-wide `make test` still stops in `tail-ipam` on current `main`: its
  `go` line is 1.27.1 while the replaced `policycore` module is 1.27.3.
