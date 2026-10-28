# Edit Delta

## ADDED Requirements

### Requirement: Posture set validates expressions before writing

The edit capability SHALL validate every expression a `posture set` writes,
against the shared `policycore/posture` grammar and vocabularies, before
the policy file is touched. An expression the control plane could not parse
SHALL fail the command as a usage error (exit 2) and the policy file SHALL
remain byte-identical, as with every other authoring error. Every other
diagnostic — an unknown `node:` or `ip:` attribute, an out-of-vocabulary
`ip:country` value — SHALL print a warning to stderr and the edit SHALL
proceed, because both vocabularies are editorial snapshots that go stale,
and an authoring command that refuses a value the server accepts is worse
than one that warns. The `--` terminator behavior SHALL be unchanged.

#### Scenario: Garbage is rejected with an unchanged file

- **WHEN** an operator runs `posture set posture:lab "this is not an
  expression"`
- **THEN** the command exits 2, the error names the expression and the
  reason, and the policy file is byte-identical afterwards

#### Scenario: An out-of-vocabulary country warns and the edit proceeds

- **WHEN** an operator runs `posture set posture:geo "ip:country NOT IN
  ['AB']"`
- **THEN** a warning naming the value prints to stderr and the posture is
  written with the expression as given, because the recorded country list
  is a snapshot that can lag the server's

#### Scenario: An unknown attribute warns and the edit proceeds

- **WHEN** an operator runs `posture set posture:bogus "node:bogusattr ==
  'x'"`
- **THEN** a warning naming the attribute prints to stderr and the posture
  is written with the expression as given
