# Check Delta

## ADDED Requirements

### Requirement: Posture gates evaluate against --posture-attr under --posture-attrs-complete

The check capability SHALL accept a repeatable `--posture-attr KEY=VALUE`
flag supplying the query's posture attributes, and a
`--posture-attrs-complete` flag asserting the supplied set is complete:
an attribute it omits is unset, so `NOT SET` matches it and every other
comparison fails. Values SHALL be typed: a JSON bool, number, or
double-quoted string keeps its type, a single-quoted value is the string
inside the quotes, and anything else is a bare string. With a complete set
the posture gate SHALL be decided: a satisfied posture opens the rule, and
a gate every posture fails is `not reachable` with the trace naming the
deciding expression and attribute. Without `--posture-attr` at all, the
gate keeps its existing indeterminate behavior and wording.

#### Scenario: A complete attribute set decides the gate

- **WHEN** `check --src alice@example.com --dst bbb:443 --posture-attr
  ip:country=KP --posture-attrs-complete` runs against the reference policy
- **THEN** check reports `not reachable` and exits 1, with the trace naming
  `ip:country KP is in ['KP', 'IR']` and the failing posture

#### Scenario: Value typing distinguishes boolean from string

- **WHEN** a query passes `--posture-attr flag=true` and another passes
  `--posture-attr flag='true'`
- **THEN** the first supplies the boolean true and the second the string
  "true"

## MODIFIED Requirements

### Requirement: An unresolvable fact is indeterminate, not a denial

The check capability SHALL exit 10 and report `indeterminate` — naming the
gating grant — when a rule that would otherwise apply depends on a fact the
policy file alone cannot supply (`via` routing, an unresolvable role
autogroup, or a posture gate that cannot be evaluated from the supplied
attributes). Without `--posture-attrs-complete`, a posture attribute the
gate reads but the query does not supply SHALL keep the query indeterminate:
"not supplied" means "not known", not "unset", and a posture that reads an
unsupplied attribute is not judged. It SHALL NOT serialize `allowed: false`
for an indeterminate result.

#### Scenario: A via-routed grant is indeterminate

- **WHEN** the only grant covering the query carries a `via` clause
- **THEN** check exits 10, stdout contains "indeterminate" and names the
  gating grant, and the JSON envelope omits the `allowed` field

#### Scenario: A needed-but-unsupplied posture attribute is indeterminate

- **WHEN** `check --src alice@example.com --dst bbb:443 --posture-attr
  ip:country=KP` runs against the reference policy without
  `--posture-attrs-complete`
- **THEN** check exits 10, reporting the posture could not be evaluated
  locally because `custom:subnet_router` was not supplied
