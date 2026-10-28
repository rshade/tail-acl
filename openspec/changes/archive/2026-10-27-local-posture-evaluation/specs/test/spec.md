# Test Delta

## ADDED Requirements

### Requirement: A test carrying srcPostureAttrs is evaluated against it

The test capability SHALL evaluate a `tests` entry carrying a
`srcPostureAttrs` key — including an empty object — against that attribute
map, treated as complete: an attribute the map omits is unset. Postures in
one `srcPosture` list SHALL be ORed and a posture's expressions ANDed, and
an unset attribute SHALL fail every comparison except `NOT SET`. A rule
whose effective posture gate is not satisfied by the map SHALL be a clean
non-match, and the assertion's decision trace SHALL name the posture,
expression, attribute, and outcome that decided the gate. An entry with no
`srcPostureAttrs` key SHALL keep the indeterminate posture gate with its
existing wording.

#### Scenario: The reference policy passes locally

- **WHEN** `test` runs against the reference policy whose seven tests were
  confirmed passing on the control plane on 2026-10-02
- **THEN** every assertion passes locally with exit 0 and no server call,
  and denies carry a trace naming the deciding expression and attribute

#### Scenario: A flipped expectation fails with the server's verdict

- **WHEN** the reference policy's third test flips `deny bbb:443` to
  `accept bbb:443`
- **THEN** that assertion fails with expected accept and actual deny, and
  the trace names `ip:country KP is in ['KP', 'IR']` and the failing posture

#### Scenario: An omitted attribute is unset

- **WHEN** a test's `srcPostureAttrs` is `{"node:os": "linux"}` and a gate's
  posture is `custom:subnet_router NOT SET` and `ip:country NOT SET`
- **THEN** the posture is satisfied and the gate opens

#### Scenario: A test without the key keeps the indeterminate gate

- **WHEN** a test with no `srcPostureAttrs` key reaches a posture-gated rule
- **THEN** the assertion is indeterminate with the existing `uses
  unsupported srcPosture` wording

#### Scenario: A posture test does not hide unrelated tests

- **WHEN** a file mixes posture and non-posture tests
- **THEN** both kinds report definite verdicts in one run

### Requirement: Unevaluable expressions stay indeterminate

The test capability SHALL report an assertion reaching a posture gate it
cannot evaluate as indeterminate with wording distinct from the attr-less
gate, naming the cause: an unparseable expression (also listed in the
policy-scoped `skipped` array), a version comparison (`node:osVersion` or
`node:tsVersion` with an ordering operator), or an undefined posture.

#### Scenario: An unparseable posture expression

- **WHEN** a referenced posture carries an expression outside the grammar
- **THEN** assertions reaching the gate are indeterminate, and the
  expression appears in `skipped` at its `postures[posture:name][index]`
  position

#### Scenario: A version comparison

- **WHEN** a referenced posture compares `node:tsVersion >= '1.8'`
- **THEN** assertions reaching the gate are indeterminate, because the
  server-side comparison is not reproduced locally
