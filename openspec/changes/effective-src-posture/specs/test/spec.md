# Test Delta

## ADDED Requirements

### Requirement: Posture gating uses the effective source posture

When the local evaluator walks a grant or ACL entry while evaluating
`tests[]` assertions, the rule SHALL be treated as posture-gated when its
effective source posture is non-empty: the rule's own `srcPosture` when it
has one, otherwise the policy's `defaultSrcPosture`. A rule with its own
`srcPosture` SHALL ignore the default. Until posture expressions evaluate
locally, a posture gate makes the affected assertions indeterminate rather
than accepted or denied, and a gate inherited from the default SHALL say so
in its evidence text.

#### Scenario: A test behind a default-gated grant is indeterminate

- **WHEN** a policy gates a grant only through `defaultSrcPosture` and a
  test asserts `accept` on traffic that grant covers
- **THEN** the assertion is indeterminate, not `PASS`, and the evidence
  names `defaultSrcPosture` as the gate's origin

#### Scenario: A policy without defaultSrcPosture is unchanged

- **WHEN** a policy sets no `defaultSrcPosture` and no rule carries
  `srcPosture`
- **THEN** every assertion keeps the verdict it had before this change
