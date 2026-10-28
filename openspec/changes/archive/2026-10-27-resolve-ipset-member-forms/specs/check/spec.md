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
policy file alone cannot supply (`via` routing, an effective source posture,
an unresolvable role autogroup, a selector naming another tailnet, or a
defined ipset whose members cannot be materialized: a member that does not
parse, a `host:` or `ipset:` reference the policy does not define, a cycle,
or an expansion past the resolver's limits). A rule's effective source
posture is its own `srcPosture` when non-empty, otherwise the policy's
`defaultSrcPosture`; a gate inherited from the default SHALL be reported
with its origin (for example, `uses unsupported srcPosture (from
defaultSrcPosture)`). Without `--posture-attrs-complete`, a posture
attribute the gate reads but the query does not supply SHALL keep the query
indeterminate: "not supplied" means "not known", not "unset", and a posture
that reads an unsupplied attribute is not judged. It SHALL NOT serialize
`allowed: false` for an indeterminate result. An `ipset:` selector the
policy does not define at all is not indeterminate; it matches nothing.

A cross-tailnet `group://<alias>/<name>` or `tag://<alias>/<name>` selector
names members of another tailnet, whose roster this policy cannot supply, so
it SHALL be treated as such an unsupplied fact rather than as a selector that
names nobody.

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

#### Scenario: A grant to an unmaterializable ipset is indeterminate

- **WHEN** the only grant covering the query names `ipset:broken`, defined
  as `["host:missing"]` with no such host in `hosts`
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

#### Scenario: A cross-tailnet source selector is indeterminate, not a denial

- **WHEN** the only ACL covering the query carries
  `group://partner/engineering` as its source and the query names a local
  user
- **THEN** check exits 10, reports `"access": "indeterminate"`, names the
  selector as one that cannot be resolved from the policy file, and omits the
  `allowed` field — rather than exiting 1 with `"access": "deny"`
