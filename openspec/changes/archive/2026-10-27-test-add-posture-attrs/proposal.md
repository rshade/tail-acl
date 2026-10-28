# Proposal: test-add-posture-attrs

## Why

`test add` takes only `--src`, `--accept`, and `--deny`, so a posture test
cannot be authored with `tail-acl` at all — changing the country in two
existing posture tests needed `sed`, which AGENTS.md asks agents to avoid
(Features write-up 05). The old "an entry carrying `srcPostureAttrs` is
never a merge target" rule existed only because the local evaluator could
not run such entries; `local-posture-evaluation` removed that reason.

## What Changes

- `test add --src-posture-attr KEY=VALUE` (repeatable) writes the typed
  attributes into a new entry's `srcPostureAttrs`, using the same value
  typing as `check --posture-attr` (the shared `ParsePostureAttrs` helper).
- Merge semantics: a posture test is identified by its source AND its
  attributes. An add carrying attributes merges only with an entry whose
  `srcPostureAttrs` is present and deep-equal after typing — the same source
  with a different country forks a second entry. A flag-less edit is
  unchanged: it matches entries with no `srcPostureAttrs` key or an empty
  one. `test remove --src-posture-attr` targets an exact attribute-map match
  under the existing renumbering rules.
- Keys are checked against the known-attribute vocabulary as a stderr
  warning only: an unknown `node:`/`ip:` or namespace-less key warns and the
  edit proceeds; a `custom:` key never warns. A repeated key is a usage
  error (exit 2), not a silent override.

## Capabilities

### New Capabilities

<!-- None. -->

### Modified Capabilities

- `test`: `test add`/`test remove` gain posture-attribute authoring and
  attribute-aware merge targeting.

## Impact

- `internal/aclpolicy/testedit.go` (`AddAssertions`/`RemoveAssertions` take
  the attribute set; `postureAttrsMatch` replaces the never-a-merge-target
  rule), `internal/aclpolicy/postureattr.go` (`PostureAttrWarnings`).
- `cmd/tail-acl/commands.go` and `main.go` (the new flags, stderr warnings),
  the `-schema` command usage strings and their golden.
- README's posture-qualified-entries bullet, command table rows, and
  examples.
