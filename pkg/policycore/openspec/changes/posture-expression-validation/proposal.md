# Proposal: posture-expression-validation

## Why

`tail-acl posture set` stores any string as a posture expression, and
`tail-acl lint` never parses expressions, so a malformed posture passes both
and only server-side `validate` catches it — reproduced against the control
plane on 2026-10-02 with all three write-up expressions (Features write-up
03). Meanwhile the repository already has a stdlib-only posture parser and
evaluator, but it lives inside `tailnet-audit` where no other tool can share
it, and its grammar predates the server's `ip:` namespace and `IS SET` /
`NOT SET` operators.

This is the `policycore` half of a change shared with `tail-acl` and
`tailnet-audit` under the slug `posture-expression-validation`. Moving the
parser here follows the repo rule that two tools must not disagree about one
policy: one grammar, one country vocabulary, one known-attribute table.

## What Changes

- Move `tailnet-audit/internal/audit/posture` to a new `policycore/posture`
  subpackage, keeping `package posture` and its public API. The Kleene
  three-valued composition in `Evaluate` is unchanged — `tailnet-audit`'s
  goldens depend on it.
- Extend the grammar: the `ip:` attribute namespace, and the `IS SET` /
  `NOT SET` operators (case-insensitive like `IN`). `IS SET` is Satisfied
  exactly when the attribute resolves, Unsatisfied when it is genuinely
  unset, and Unknown when the capture cannot say; `NOT SET` is the mirror.
  The bare truthy form is kept exactly as-is.
- Add an offline validation API, `Validate(expression) []Diagnostic`, with
  three kinds: `DiagnosticUnparseable` (error-level; the control plane
  rejects these), `DiagnosticUnknownValue` (error-level; an `ip:country`
  value outside the recorded vocabulary), and `DiagnosticUnknownAttribute`
  (warning-level; the known-attribute table is editorial and goes stale).
  `custom:` attributes are user-defined and are never checked.
- Record the server's accepted `ip:country` list — captured live on
  2026-10-02, 250 codes including `XK` and excluding `ZZ` — as a
  `posture/testdata` fixture that is the source of truth for the package
  vocabulary, with a Tier-2 provenance guard test and an opt-in
  `live_verify` test that re-derives the list from the control plane and
  fails on drift.

## Capabilities

### New Capabilities

<!-- None. The `posture` capability arrives with `effective-src-posture`. -->

### Modified Capabilities

- `posture`: gains the expression grammar, the set operators, and the
  offline validation contract.

## Impact

- New subpackage `policycore/posture` (parser moved from `tailnet-audit`,
  extended grammar, `validate.go`, fixtures and guard tests under
  `posture/testdata/`).
- `policycore/README.md`, the `address.go` package doc, and
  `docs/public-api.md` stop saying posture stays out of `policycore`.
- `tail-acl` (lint rule + `posture set` validation) and `tailnet-audit`
  (adopt the moved parser) carry their halves under the same slug.
