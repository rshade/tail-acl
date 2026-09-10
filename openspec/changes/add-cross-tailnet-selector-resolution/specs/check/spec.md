# Check Spec Delta

## MODIFIED Requirements

### Requirement: An unresolvable fact is indeterminate, not a denial

The check capability SHALL exit 10 and report `indeterminate` — naming the
gating grant — when a rule that would otherwise apply depends on a fact the
policy file alone cannot supply (`via` routing, `srcPosture`, an unresolvable
role autogroup, or a selector naming another tailnet). It SHALL NOT serialize
`allowed: false` for an indeterminate result.

A cross-tailnet `group://<alias>/<name>` or `tag://<alias>/<name>` selector
names members of another tailnet, whose roster this policy cannot supply, so
it SHALL be treated as such an unsupplied fact rather than as a selector that
names nobody.

#### Scenario: A via-routed grant is indeterminate

- **WHEN** the only grant covering the query carries a `via` clause
- **THEN** check exits 10, stdout contains "indeterminate" and names the
  gating grant, and the JSON envelope omits the `allowed` field

#### Scenario: A cross-tailnet source selector is indeterminate, not a denial

- **WHEN** the only ACL covering the query carries
  `group://partner/engineering` as its source and the query names a local
  user
- **THEN** check exits 10, reports `"access": "indeterminate"`, names the
  selector as one that cannot be resolved from the policy file, and omits the
  `allowed` field — rather than exiting 1 with `"access": "deny"`
