# Normalize Specification

## Purpose

Emit the policy as standard JSON for general-purpose JSON tools, without
modifying the source file.

## Requirements

### Requirement: Human output is bare standard JSON with no envelope

The normalize capability's human-format output SHALL be exactly the
standardized JSON bytes on stdout — no envelope, banner, or trailing summary
line — and SHALL NOT modify the source `--file`.

#### Scenario: stdout is exactly the normalized bytes

- **WHEN** `normalize` runs in human format against a HuJSON policy
- **THEN** stdout equals the library's standardized JSON byte-for-byte, stderr
  is empty, and the source file is unchanged

### Requirement: JSON format wraps the policy in the versioned envelope

The normalize capability's `-format json` output SHALL carry the standardized
policy under the envelope's `policy` field rather than emitting it bare.

#### Scenario: JSON format is the envelope, not the bare policy

- **WHEN** `normalize -format json` runs
- **THEN** the decoded envelope has `schema_version`, `command: "normalize"`,
  `status: "ok"`, and a `policy` field holding valid JSON distinct from the
  raw stdout bytes

### Requirement: Invalid input is a usage error with no stdout

The normalize capability SHALL exit 2 and write nothing to stdout when
`--file` does not parse as valid HuJSON, and SHALL name the source path in the
error.

#### Scenario: Malformed HuJSON produces no output

- **WHEN** `normalize` runs against a file containing unterminated HuJSON
- **THEN** the command exits 2, stdout is empty, and the error names the file

### Requirement: Active sanitization is refused

The normalize capability SHALL refuse to run under a non-off `--sanitize`
level, because normalized policy bytes cannot be mechanically sanitized.

#### Scenario: Sanitize strict is rejected

- **WHEN** `normalize` runs with `--sanitize strict`
- **THEN** the command exits 2 and states that its output cannot be
  mechanically sanitized
