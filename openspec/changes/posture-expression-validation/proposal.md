# Proposal: posture-expression-validation

## Why

`posture set` stores any string as a posture expression and `lint` never
parses expressions, so every malformed posture in the Features/03 write-up
passed both and only server-side `validate` caught it — including
`ip:country NOT IN ['AB', 'CD']`, the placeholder country code that blocked
a real policy when the server rejected the whole document over it
(reproduced against the control plane on 2026-10-02).

This is the `tail-acl` half of a change shared with `policycore` and
`tailnet-audit` under the slug `posture-expression-validation`. The grammar
and vocabularies live in `policycore/posture`; this change wires them into
lint and authoring.

## What Changes

- New `posture-invalid` lint rule: every expression in every `postures`
  entry runs through `policycore/posture`'s validator. An unparseable
  expression or an out-of-vocabulary `ip:country` value is an error (the
  control plane rejects the policy over both); an unknown `node:`/`ip:`
  attribute is a warn, because the known-attribute table is editorial and
  goes stale. The finding names the posture, the expression, and the
  reason, located as `postures[posture:name][index]`.
- `posture set` validates each expression before writing. An unparseable
  expression is a usage error (exit 2) and leaves the policy file
  byte-identical, the contract every other authoring error keeps. A
  stale-vocabulary diagnostic — an unknown attribute or an
  out-of-vocabulary `ip:country` value — prints to stderr and the edit
  proceeds: an authoring command that refuses a value the server accepts
  is worse than one that warns. The `--` terminator behavior is unchanged.

## Capabilities

### New Capabilities

<!-- None. -->

### Modified Capabilities

- `lint`: gains the `posture-invalid` finding class.
- `edit`: `posture set` gains expression validation.

## Impact

- `internal/aclpolicy/lint.go` (rule ID, catalog entry, driver), the
  `-schema` lint_findings catalog and its golden, the README lint table.
- `cmd/tail-acl/main.go` (`runPostureSet` validates before patching) and
  `commands.go` (stderr reaches the command for warnings).
- `policycore` carries the parser and validator under the same slug;
  `tailnet-audit` adopts the moved parser.
