# Lint Spec Delta

## ADDED Requirements

### Requirement: An ipset mixing implicit members with a remove is an error

The lint capability SHALL report `ipset-mixed-operations` at `error`
severity for every ipset whose members include a `remove <member>` operation
alongside any member that is not an explicit `add <member>` or
`remove <member>`. The finding SHALL locate the ipset as `ipsets[<name>]`,
carry the first implicit member as its value, and recommend the
`add <member>` spelling. A set whose members are all explicit, or one with
no `remove`, SHALL NOT be reported.

#### Scenario: A hand-written mixed set is reported

- **WHEN** `ipsets` defines `ipset:x` as
  `["ipset:base", "remove 10.1.0.0/16"]`
- **THEN** lint reports one `ipset-mixed-operations` error at
  `ipsets[ipset:x]` with value `ipset:base` and the run exits 1

#### Scenario: An all-explicit set is clean

- **WHEN** `ipsets` defines `ipset:x` as
  `["add ipset:base", "remove 10.1.0.0/16"]`
- **THEN** lint reports no `ipset-mixed-operations` finding

### Requirement: References inside ipset members count as uses

The lint capability's unused-definition checks SHALL treat an `ipset:` or
`host:` reference inside another ipset's members — bare or under an
`add`/`remove` operation — as a reference to that ipset or host alias.

#### Scenario: A nested-only ipset is not unused

- **WHEN** `ipset:base` is referenced only as `add ipset:base` inside an
  ipset that a grant names
- **THEN** lint reports no `unused-ipset` finding for `ipset:base`
