# Lint Specification

## Purpose

Statically lint policy hygiene — dangling references, over-broad wildcard
rules, and untested broad rules — entirely offline by default, with an
optional read-only online check against the control plane.

## Requirements

### Requirement: Findings are reported with severity and a summary line

The lint capability SHALL emit one line per finding, each carrying its
severity, check ID, locator, and evidence, and SHALL summarize counts by
severity. A policy with no findings SHALL report "no policy hygiene
findings" and exit 0; findings at or above the resolved severity threshold
SHALL exit 1.

#### Scenario: Dangling references are reported and fail

- **WHEN** a grant's `dst` references an undefined tag and its `src`
  references an undefined group
- **THEN** stdout shows an `ERROR` line for each and
  `tail-acl: 2 findings: 2 error, 0 warn, 0 info`, and the command exits 1

#### Scenario: A clean policy passes

- **WHEN** every group, tag, and reference in the policy is defined
- **THEN** stdout reports "no policy hygiene findings" and the command exits
  0

### Requirement: --severity sets a single floor for both display and exit

The lint capability's `--severity` (`advice|info|warn|error`) SHALL determine
both which findings the human view displays and which findings can fail the
run; omitting the flag SHALL display every finding while still failing at
`warn` or above.

#### Scenario: Advice findings do not fail by default

- **WHEN** lint's only findings are `advice` severity and `--severity` is
  omitted
- **THEN** the findings are displayed under an advisory caption and the
  command exits 0

### Requirement: Lint runs offline unless --online-validation is given

The lint capability SHALL evaluate every check against the local policy file
alone by default, requiring no HTTP client or credentials. `--online-validation`
SHALL additionally check `svc:` destinations and SCIM group sync against the
control plane when `--tailnet` and an API key or OAuth credentials are
supplied; when either is missing, it SHALL log a warning and skip the online
check rather than failing the run, and SHALL still report the offline
findings already computed either way.

#### Scenario: Default lint needs no network access

- **WHEN** `lint` runs without `--online-validation` and with no HTTP client
  configured
- **THEN** the command still evaluates and reports all offline findings

#### Scenario: --online-validation without credentials degrades to a logged skip

- **WHEN** `--online-validation` runs with no `--tailnet` or no credentials
  supplied
- **THEN** the command logs "skipping online validation: missing credentials"
  to stderr, still reports the offline findings, and does not fail on that
  account alone

#### Scenario: An OAuth client without vip-services scope skips svc-unknown checks

- **WHEN** `--online-validation` runs with OAuth client credentials that
  cannot read vip-services
- **THEN** `svc-unknown` findings for that policy are skipped rather than
  failing the run

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
