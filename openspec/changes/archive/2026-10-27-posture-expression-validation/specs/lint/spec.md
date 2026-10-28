# Lint Delta

## ADDED Requirements

### Requirement: Posture expressions are validated statically

The lint capability SHALL run every expression of every `postures` entry
through the shared `policycore/posture` validator and SHALL report a
`posture-invalid` finding per diagnostic. An unparseable expression and an
`ip:country` value outside the recorded vocabulary SHALL be error findings,
because the control plane rejects the policy over both; an unknown `node:`
or `ip:` attribute SHALL be a warn finding, because the known-attribute
table is editorial and can lag the server. The finding SHALL name the
posture, the expression, and the reason, located as
`postures[posture:name][index]`.

#### Scenario: An out-of-vocabulary country is an error

- **WHEN** `postures` defines `posture:geo` with the expression
  `ip:country NOT IN ['AB', 'CD']`
- **THEN** lint reports a `posture-invalid` error at
  `postures[posture:geo][0]` naming `posture:geo`, the expression, and
  `unexpected value "AB"`

#### Scenario: An unparseable expression is an error

- **WHEN** `postures` defines a posture with the expression `this is not an
  expression`
- **THEN** lint reports a `posture-invalid` error naming the expression and
  the valid operator list

#### Scenario: An unknown attribute only warns

- **WHEN** `postures` defines a posture with the expression
  `node:bogusattr == 'x'`
- **THEN** lint reports a `posture-invalid` warn naming the attribute,
  because the known-attribute table is editorial and goes stale
