# Check Delta

## MODIFIED Requirements

### Requirement: An unresolvable fact is indeterminate, not a denial

The check capability SHALL exit 10 and report `indeterminate` — naming the
gating grant — when a rule that would otherwise apply depends on a fact the
policy file alone cannot supply (`via` routing, an effective source posture,
or an unresolvable role autogroup). A rule's effective source posture is its
own `srcPosture` when non-empty, otherwise the policy's
`defaultSrcPosture`; a gate inherited from the default SHALL be reported
with its origin (for example, `uses unsupported srcPosture (from
defaultSrcPosture)`). It SHALL NOT serialize `allowed: false` for an
indeterminate result.

#### Scenario: A via-routed grant is indeterminate

- **WHEN** the only grant covering the query carries a `via` clause
- **THEN** check exits 10, stdout contains "indeterminate" and names the
  gating grant, and the JSON envelope omits the `allowed` field

#### Scenario: A grant gated only by defaultSrcPosture is indeterminate

- **WHEN** the only grant covering the query has no `srcPosture` and the
  policy sets `defaultSrcPosture`
- **THEN** check exits 10, stdout contains "indeterminate", names the
  gating grant, and the evidence says the posture came from
  `defaultSrcPosture`

#### Scenario: A rule's own posture replaces the default

- **WHEN** a grant carries its own `srcPosture` and the policy also sets
  `defaultSrcPosture`
- **THEN** the gate reports the rule's own posture without the default
  origin suffix
