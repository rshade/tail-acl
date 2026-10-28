# posture Specification

## Purpose

Resolve a rule's effective source-posture gate: the rule's own `srcPosture`
when that list is non-empty, otherwise the tailnet `defaultSrcPosture`.

## Requirements

### Requirement: Effective source posture is the rule's own posture, else the tailnet default

A rule's effective source-posture gate SHALL be its own `srcPosture` list
when that list is non-empty, and the policy's `defaultSrcPosture` otherwise.
The default SHALL NOT be added to a rule's own posture: a rule with its own
`srcPosture` is gated by exactly that list. The helper
`EffectiveSrcPosture(own, fallback)` SHALL return the effective list and
whether it came from the fallback, so a caller can name the origin of a
gate.

#### Scenario: A rule with its own posture replaces the default

- **WHEN** a grant has `srcPosture: ["posture:a"]` and the policy sets
  `defaultSrcPosture: ["posture:b"]`
- **THEN** the effective posture is `["posture:a"]` and the origin is the
  rule

#### Scenario: A rule without its own posture inherits the default

- **WHEN** a grant has no `srcPosture` and the policy sets
  `defaultSrcPosture: ["posture:b"]`
- **THEN** the effective posture is `["posture:b"]` and the origin is the
  default

#### Scenario: No posture anywhere is no gate

- **WHEN** a grant has no `srcPosture` and the policy sets no
  `defaultSrcPosture`
- **THEN** the effective posture is empty

### Requirement: Posture expressions parse one shared grammar

The posture capability SHALL parse a posture rule expression as an attribute
in the `node:`, `custom:`, or `ip:` namespace followed by an operator and
operand: a comparison operator (`==`, `!=`, `<`, `<=`, `>`, `>=`) with a
quoted-string, number, or boolean literal; a case-insensitive `IN` /
`NOT IN` membership operator with a bracketed literal list; or a
case-insensitive `IS SET` / `NOT SET` set operator with no operand. The bare
truthy form (an attribute alone) SHALL remain part of the grammar. Anything
outside the grammar SHALL be rejected rather than guessed at, and an
expression that cannot be parsed SHALL evaluate as Unknown with a reason,
never as a pass or a failure.

#### Scenario: The ip namespace parses

- **WHEN** a posture rule is `ip:country IN ['US', 'XK']`
- **THEN** the expression parses and evaluates against a device carrying
  `ip:country`

#### Scenario: Garbage is rejected, not guessed

- **WHEN** a posture rule is `this is not an expression`
- **THEN** the expression does not parse, and evaluating it reports Unknown
  naming the expression

### Requirement: Set operators evaluate against the resolution tri-state

`IS SET` SHALL be Satisfied exactly when the attribute resolves to a value,
Unsatisfied when the attribute is genuinely unset (including expired), and
Unknown when the capture cannot say. `NOT SET` SHALL be the mirror:
Satisfied when the attribute is unset, Unsatisfied when it resolves, and
Unknown when the capture cannot say. An `ip:` attribute the capture cannot
carry SHALL be Unknown — missing data — never treated as an unset attribute.

#### Scenario: NOT SET is satisfied by an unset attribute

- **WHEN** a device's collected attributes carry no `custom:missing` and the
  rule is `custom:missing NOT SET`
- **THEN** the rule is Satisfied

#### Scenario: IS SET is unknown when the capture cannot carry the attribute

- **WHEN** a device's collected attributes carry no `ip:country` and the rule
  is `ip:country IS SET`
- **THEN** the rule is Unknown with a reason naming the missing capture, not
  Unsatisfied

#### Scenario: An expired attribute is unset for the set operators

- **WHEN** `custom:approved` expired before the capture time and the rule is
  `custom:approved NOT SET`
- **THEN** the rule is Satisfied

### Requirement: Offline validation reports what the control plane would reject

The posture capability SHALL provide `Validate(expression) []Diagnostic`,
classifying each finding as `DiagnosticUnparseable` or
`DiagnosticUnknownValue` (error-level) or `DiagnosticUnknownAttribute`
(warning-level), with a reason mirroring the control plane's own message
wording where that wording is known from live probes. An expression outside
the grammar SHALL produce an unparseable diagnostic whose reason lists the
valid operators when the operator is what failed. The bare truthy form on a
known non-boolean built-in attribute SHALL produce an unparseable diagnostic
mirroring the server's `can only be compared to string, got bool: true`
wording; the bare form on a `custom:` or unknown attribute SHALL produce no
diagnostic. A `custom:` attribute's name or value SHALL never be checked.

#### Scenario: An unparseable expression names the valid operators

- **WHEN** `Validate` runs on `this is not an expression`
- **THEN** the finding is unparseable and its reason reads `expected an
  operator, found: "is not an"` followed by the valid operator list

#### Scenario: An unknown built-in attribute warns

- **WHEN** `Validate` runs on `node:bogusattr == 'x'`
- **THEN** the finding is warning-level `attribute "node:bogusattr" does not
  exist`, because the known-attribute table is editorial and goes stale

#### Scenario: The bare form on a known string attribute mirrors the server

- **WHEN** `Validate` runs on `node:os`
- **THEN** the finding is unparseable with the reason `built-in attribute
  "node:os" can only be compared to string, got bool: true`

#### Scenario: A custom attribute is never flagged

- **WHEN** `Validate` runs on `custom:totallyMadeUp == 'anything'`
- **THEN** there is no diagnostic

### Requirement: The ip:country vocabulary is a captured fixture

The posture capability SHALL check `ip:country` values against the control
plane's accepted country list as captured live on 2026-10-02 (250 codes,
including `XK` and excluding `ZZ`), recorded as a fixture under
`posture/testdata/` with provenance. A value outside the recorded vocabulary
SHALL produce an error-level `DiagnosticUnknownValue` mirroring the server's
`unexpected value` wording, including the list index for membership
expressions. A hand-written Tier-2 guard test SHALL pin the package
vocabulary against the fixture, and an opt-in `live_verify` test SHALL
re-derive the list from a control-plane validation error and fail on drift.

#### Scenario: An invalid country is flagged with its list index

- **WHEN** `Validate` runs on `ip:country NOT IN ['AB', 'CD']`
- **THEN** exactly one error-level finding flags `"AB"` at list index 0,
  because `CD` is in the recorded vocabulary

#### Scenario: XK is accepted

- **WHEN** `Validate` runs on `ip:country IN ['US', 'XK']`
- **THEN** there is no diagnostic

#### Scenario: The guard fails on drift from the fixture

- **WHEN** the package vocabulary and the fixture disagree
- **THEN** the guard test fails, naming the codes that differ
