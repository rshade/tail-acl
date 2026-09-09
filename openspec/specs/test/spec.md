# Test Specification

## Purpose

Run the policy's own `tests[]` network assertions locally (`test`), author
them without evaluating (`test add`/`test remove`), and optionally watch the
policy file for changes.

## Requirements

### Requirement: Declared assertions are evaluated locally with a pass/fail summary

The test capability SHALL evaluate every `tests[]` entry's `accept` and
`deny` destinations against the policy locally, print one `PASS`/`FAIL` line
per assertion, and summarize the count. It SHALL exit 0 when every assertion
passes and exit 1 when any fails.

#### Scenario: All assertions pass

- **WHEN** `test` runs against a policy whose declared `accept`/`deny`
  assertions are all satisfied by its grants
- **THEN** stdout shows one `PASS` line per assertion and
  `tail-acl: N assertions: N passed, 0 failed`, and the command exits 0

#### Scenario: A failing assertion exits 1

- **WHEN** a `deny` assertion's destination is actually reachable
- **THEN** stdout shows a `FAIL` line for it and the command exits 1

#### Scenario: No declared tests is a clean no-op

- **WHEN** the policy has no `tests` key
- **THEN** stdout reports "no policy tests declared" and the command exits 0

### Requirement: test add appends assertions without evaluating them

The test capability's `add` subcommand SHALL append `--deny`/`--accept`
destinations for `--src` to the policy's `tests[]` without evaluating them,
and SHALL report the resulting assertion IDs; it SHALL never renumber
existing assertion IDs.

#### Scenario: Added assertions get positional IDs

- **WHEN** `test add --src alice@example.com --deny tag:db:5432
  --accept tag:web:443` runs against an empty `tests[]`
- **THEN** the result's `assertion_ids` are
  `["tests[0].deny[0]", "tests[0].accept[0]"]`

### Requirement: --indeterminate governs only test's own exit code

The test capability's `--indeterminate` flag (`fail|warn|ignore`) SHALL
control how an assertion that cannot be settled from the policy alone maps
to test's exit code, and SHALL be rejected as a usage error on every command
other than `test`.

#### Scenario: --indeterminate is rejected outside test

- **WHEN** `--indeterminate=fail` is supplied to a command other than `test`
- **THEN** the command exits 2 and states that `--indeterminate` applies
  only to test

### Requirement: --watch never exits non-zero for a verdict

The test capability's `--watch` mode SHALL re-run assertions whenever the
policy file changes and SHALL exit 0 on interrupt regardless of the last
verdict, since a running watch has no single point-in-time result.

#### Scenario: Watch re-runs on a save

- **WHEN** `test --watch` is running and the policy file is saved with a
  changed, stable assertion outcome
- **THEN** a new result is emitted for the new snapshot without the process
  exiting
