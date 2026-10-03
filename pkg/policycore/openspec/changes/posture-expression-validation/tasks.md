# Tasks: posture-expression-validation

## 1. Move

- [x] 1.1 Move `tailnet-audit/internal/audit/posture` (parser and tests) to
  `policycore/posture`, keeping `package posture` and the public API, with
  the moved tests green before any extension. Verify with
  `go test ./posture/`

## 2. Grammar

- [x] 2.1 Add the `ip:` attribute namespace and the `IS SET` / `NOT SET`
  operators (case-insensitive), wired into evaluation against the resolution
  tri-state, with the bare form and the Kleene composition unchanged. Verify
  with table tests for every `posture` delta scenario:
  `go test -run 'SetOperators|IPNamespace|UnsetAttribute' ./posture/`

## 3. Validation API

- [x] 3.1 Add `Validate(expression) []Diagnostic` with the three
  `DiagnosticKind`s, `ErrorLevel`, server-mirrored reasons, the known-attribute
  table, and the `ip:country` vocabulary built from the embedded fixture.
  Verify with `go test -run 'Validate|DiagnosticKind' ./posture/`

## 4. Vocabulary guards

- [x] 4.1 Copy the 2026-10-02 country capture into `posture/testdata/` with
  provenance, add the hand-written Tier-2 guard (250 codes, XK present, ZZ
  absent) and the known-attribute table guard. Verify with
  `go test -run 'CountryVocabularyMatchesFixture|KnownAttributeTable' ./posture/`
- [x] 4.2 Add the opt-in `//go:build live_verify` test that re-derives the
  country list from a control-plane validation error. Verify with
  `go vet -tags live_verify ./posture/`

## 5. Docs and gates

- [x] 5.1 Update `policycore/README.md`, the `address.go` package doc, and
  `docs/public-api.md` for the new subpackage. Verify with
  `make lint-md` from the repository root
- [x] 5.2 Run `go test ./...` in `policycore`, `golangci-lint run ./posture/...`,
  and `openspec validate posture-expression-validation` in `policycore`.
  Verify all are green
