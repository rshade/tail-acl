# Check Specification

## Purpose

Answer one ad hoc reachability question against the local policy: can `--src`
reach `--dst` (optionally with `--port`/`--proto`)?

## Requirements

### Requirement: A definite verdict names the matching or excluding evidence

The check capability SHALL report `reachable` when a grant or ACL rule
matches the source, destination, and protocol, and `not reachable` otherwise,
naming the matched grant index or stating that no rule matched.

#### Scenario: A matching grant is reachable

- **WHEN** `check --src alice@example.com --dst tag:web:443` runs against a
  policy where a grant permits that path
- **THEN** stdout reports `reachable: alice@example.com -> tag:web:443` and
  names "matched grant 0", and the command exits 0

#### Scenario: No matching rule is not reachable

- **WHEN** `check` asks about a destination no grant permits
- **THEN** stdout reports "not reachable" and states no grant or ACL matched,
  and the command exits 1

### Requirement: An unresolvable fact is indeterminate, not a denial

The check capability SHALL exit 10 and report `indeterminate` — naming the
gating grant — when a rule that would otherwise apply depends on a fact the
policy file alone cannot supply (`via` routing, `srcPosture`, or an
unresolvable role autogroup). It SHALL NOT serialize `allowed: false` for an
indeterminate result.

#### Scenario: A via-routed grant is indeterminate

- **WHEN** the only grant covering the query carries a `via` clause
- **THEN** check exits 10, stdout contains "indeterminate" and names the
  gating grant, and the JSON envelope omits the `allowed` field

### Requirement: --proto narrows the question; the default is protocol-agnostic

The check capability SHALL restrict matching to the given `--proto`
(`tcp|udp|sctp|any`) when supplied, and SHALL match any protocol by default.
An unknown `--proto` value SHALL be a usage error.

#### Scenario: Default check matches regardless of protocol

- **WHEN** `check` runs without `--proto` against a grant scoped to `udp`
- **THEN** the destination is reported reachable

#### Scenario: Unknown protocol is a usage error

- **WHEN** `check` runs with `--proto quic`
- **THEN** the command exits 2
