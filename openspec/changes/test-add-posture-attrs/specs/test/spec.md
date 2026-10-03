# Test Delta

## ADDED Requirements

### Requirement: test add and test remove author posture attributes

The test capability's `add` and `remove` subcommands SHALL accept a
repeatable `--src-posture-attr KEY=VALUE` flag. On `add`, the typed
attributes SHALL be written into a new entry's `srcPostureAttrs`. Values
SHALL be typed exactly as `check`'s `--posture-attr` types them, so a value
written by `test add` is the value `check` asks about. Keys SHALL be checked
against the known-attribute vocabulary as a stderr warning only: an unknown
`node:`/`ip:` or namespace-less key warns and the edit proceeds, and a
`custom:` key never warns. A repeated key SHALL be a usage error (exit 2)
with the policy file byte-identical.

#### Scenario: Authoring the reference posture test

- **WHEN** `test add --src alice@example.com --src-posture-attr
  node:os=linux --src-posture-attr ip:country=KP --deny bbb:443 --deny
  nyc-svc:443` runs against a policy whose tests list is empty
- **THEN** the new entry carries `srcPostureAttrs` `{"node:os": "linux",
  "ip:country": "KP"}` and both denies, matching the reference policy's
  server-confirmed entry

#### Scenario: An unknown attribute key warns and proceeds

- **WHEN** `test add` runs with `--src-posture-attr node:bogusattr=x`
- **THEN** a warning naming the unknown attribute prints to stderr and the
  entry is written

#### Scenario: A repeated key is a usage error

- **WHEN** `test add` runs with `--src-posture-attr ip:country=KP
  --src-posture-attr ip:country=IR`
- **THEN** the command exits 2 and the policy file is unchanged

### Requirement: A posture test is identified by source and attributes

An edit carrying `--src-posture-attr` SHALL target only an entry whose
`srcPostureAttrs` is present and deep-equal after value typing: an `add`
merges into that entry (a re-run reports `no_changes`), and forks a new
entry on any attribute difference; a `remove` targets only an exact
attribute-map match under the existing renumbering rules. An edit without
the flags SHALL match only entries with no `srcPostureAttrs` key or an
empty one.

#### Scenario: Re-running an add is idempotent

- **WHEN** the same `test add --src-posture-attr ...` command runs twice
- **THEN** the second run reports `no_changes`

#### Scenario: A different country forks a second entry

- **WHEN** an entry exists for a source with `ip:country: "KP"` and `test
  add` runs for the same source with `ip:country=IR`
- **THEN** a second entry is created rather than a merge

#### Scenario: Removal targets only the exact attribute set

- **WHEN** two entries share a source with different `ip:country` values and
  `test remove` names one of them with `--src-posture-attr`
- **THEN** only the matching entry's assertions are removed

#### Scenario: A flag-less edit skips posture-qualified entries

- **WHEN** `test add` or `test remove` runs without `--src-posture-attr`
  against an entry carrying a non-empty `srcPostureAttrs`
- **THEN** that entry is not a target; entries with no key or an empty
  object are

## MODIFIED Requirements

### Requirement: test add appends assertions without evaluating them

The test capability's `add` subcommand SHALL append `--deny`/`--accept`
destinations for `--src` to the policy's `tests[]` without evaluating them,
and SHALL report the resulting assertion IDs; it SHALL never renumber
existing assertion IDs. When `--src-posture-attr` is supplied the
destination entry is the one whose source AND attribute set match, per the
source-and-attributes identity rule.

#### Scenario: Added assertions get positional IDs

- **WHEN** `test add --src alice@example.com --deny tag:db:5432
  --accept tag:web:443` runs against an empty `tests[]`
- **THEN** the result's `assertion_ids` are
  `["tests[0].deny[0]", "tests[0].accept[0]"]`

#### Scenario: A posture add reports the matching entry's IDs

- **WHEN** `test add --src alice@example.com --src-posture-attr
  ip:country=KP --deny bbb:443` runs against an entry with the same source
  and attributes that already denies `bbb:443`
- **THEN** the result is `no_changes` and its `assertion_ids` point into the
  matching entry
