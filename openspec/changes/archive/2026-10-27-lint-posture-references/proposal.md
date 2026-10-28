# Proposal: lint-posture-references

## Why

The README's posture-authoring section says the dangling-reference check is
`lint`'s job, and the doc comment on `ValidatePostureReference` says the
same — but `lint` has no posture rule at all, so a typo'd `posture:` name
passes authoring, passes `lint`, and only server-side `validate` catches it
(reproduced 2026-10-02; Features write-up 02). Authoring and lint each claim
the other checks this.

## What Changes

- `lint` flags a `srcPosture` entry in a grant or ACL entry, or a
  `defaultSrcPosture` entry, that names a posture missing from `postures`,
  under the existing `undefined-reference` rule (error): a posture name is a
  reference like a group name. Names resolve with `NormalizePostureName`,
  the same function `posture set`/`remove` use, so lint and authoring agree
  on what a name refers to.
- New `unused-posture` rule (info): a posture defined in `postures` that no
  `srcPosture` or `defaultSrcPosture` references. A reference from
  `defaultSrcPosture` counts, so a policy gating everything through the
  default does not flag every posture it uses.

## Capabilities

### New Capabilities

<!-- None. -->

### Modified Capabilities

- `lint`: gains posture reference resolution and the `unused-posture`
  finding class.

## Impact

- `internal/aclpolicy/lint.go` (reference walk, unused-definition walk,
  catalog), the `-schema` lint_findings catalog and its golden, the README
  lint table and the posture-authoring paragraph that currently (falsely)
  says lint has no posture handling.
- The guard test that pins posture out of lint
  (`TestEvaluateLintDoesNotFlagSrcPostureOrPostures`) is replaced by
  positive tests.
