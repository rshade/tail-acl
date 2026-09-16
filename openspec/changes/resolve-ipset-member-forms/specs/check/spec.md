# Check Delta

## ADDED Requirements

### Requirement: Ipset member forms resolve in a verdict

The check capability SHALL resolve a destination or source that names an
ipset through every member form the control plane accepts: a set with `add`
and `remove` operations matches an address the operations leave in the set
and not one they withdrew, a range matches every address between its ends
inclusive, and a `host:` reference matches the aliased host's address.

#### Scenario: The four measured cases report the control plane's verdicts

- **WHEN** the policy defines `hosts: {gw: 10.9.0.1}`, `ipset:base:
  ["10.0.0.0/8"]`, `ipset:trimmed: ["add ipset:base", "remove 10.1.0.0/16"]`,
  `ipset:rng: ["10.5.0.1-10.5.0.9"]`, `ipset:h: ["host:gw"]`, and a grant
  from `tag:web` to `ipset:trimmed`, `ipset:rng`, and `ipset:h` on `tcp:*`
- **THEN** `check --src tag:web --dst 10.1.0.5:80` reports `not reachable`,
  and `--dst 10.2.0.5:80`, `--dst 10.5.0.4:81`, and `--dst 10.9.0.1:82` each
  report `reachable` naming the matched grant

## MODIFIED Requirements

### Requirement: An unresolvable fact is indeterminate, not a denial

The check capability SHALL exit 10 and report `indeterminate` — naming the
gating grant — when a rule that would otherwise apply depends on a fact the
policy file alone cannot supply (`via` routing, `srcPosture`, an
unresolvable role autogroup, or a defined ipset whose members cannot be
materialized: a member that does not parse, a `host:` or `ipset:` reference
the policy does not define, a cycle, or an expansion past the resolver's
limits). It SHALL NOT serialize `allowed: false` for an indeterminate
result. An `ipset:` selector the policy does not define at all is not
indeterminate; it matches nothing.

#### Scenario: A via-routed grant is indeterminate

- **WHEN** the only grant covering the query carries a `via` clause
- **THEN** check exits 10, stdout contains "indeterminate" and names the
  gating grant, and the JSON envelope omits the `allowed` field

#### Scenario: A grant to an unmaterializable ipset is indeterminate

- **WHEN** the only grant covering the query names `ipset:broken`, defined
  as `["host:missing"]` with no such host in `hosts`
- **THEN** check exits 10, stdout contains "indeterminate" and names the
  gating grant, and the JSON envelope omits the `allowed` field
