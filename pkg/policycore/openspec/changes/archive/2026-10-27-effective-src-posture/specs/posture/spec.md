# Posture Delta

## ADDED Requirements

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
