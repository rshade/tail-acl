# Lint Delta

## ADDED Requirements

### Requirement: Overlapping auto-approver routes warn

Lint SHALL report one `autoapprover-route-overlap` warning for each pair of
`autoApprovers.routes` keys that, after `NormalizeAutoApproverRoute`, name
the same CIDR or name two CIDRs whose ranges overlap. The finding SHALL
name both keys. A key that is not a CIDR SHALL be ignored by this check.
The check SHALL NOT call the control plane.

#### Scenario: Two spellings of one CIDR warn

- **WHEN** the routes are `10.0.0.1/8` and `10.0.0.0/8`
- **THEN** lint reports one `autoapprover-route-overlap` warning naming
  both keys

#### Scenario: Two overlapping CIDRs warn

- **WHEN** the routes are `10.0.0.0/24` and `10.0.0.128/25`
- **THEN** lint reports one `autoapprover-route-overlap` warning naming
  both keys

#### Scenario: Disjoint routes are clean

- **WHEN** the routes are `10.0.0.0/24` and `10.1.0.0/24`
- **THEN** lint reports no `autoapprover-route-overlap` finding

### Requirement: Via-prefix pairs are excluded

Lint SHALL NOT report `autoapprover-route-overlap` for a pair of keys that
both parse as 4via6 via prefixes.

#### Scenario: Two via prefixes do not use this finding

- **WHEN** both route keys are via prefixes, even if their ranges overlap
- **THEN** lint reports no `autoapprover-route-overlap` finding

#### Scenario: A via prefix beside an IPv4 route is not this finding

- **WHEN** one key is a via prefix and the other is `10.0.0.0/8`
- **THEN** lint reports no `autoapprover-route-overlap` finding
