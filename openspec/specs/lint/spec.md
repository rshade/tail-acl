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
  `tsacl: 2 findings: 2 error, 0 warn, 0 info`, and the command exits 1

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

### Requirement: External tailnet allow-lists count as uses

The lint capability's unused-definition checks SHALL treat every selector in
`externalTailnets[<alias>].allowExternalReferencesTo` as a reference to that
definition. A group or tag named only there SHALL NOT be reported unused.
The unused-definition decision trace SHALL name `externalTailnets` among the
fields that were searched.

#### Scenario: A group exposed only to an external tailnet is used

- **WHEN** `group:eng` is defined and the only reference to it is
  `externalTailnets.partner.allowExternalReferencesTo`
- **THEN** lint reports no `unused-group` finding for `group:eng`

#### Scenario: The unused-definition trace names externalTailnets

- **WHEN** lint reports an unused definition
- **THEN** that finding's decision trace says the search included
  `externalTailnets`

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

### Requirement: Shared via site IDs are advice

Lint SHALL report one `autoapprover-siteid-collision` advice finding when
two or more `autoApprovers.routes` via prefixes share a site ID and their
embedded IPv4 prefixes differ. The finding SHALL name each of those routes
and SHALL ask the reader to confirm they are the same site. It SHALL NOT
call the control plane, and it SHALL NOT use warn or error severity.

#### Scenario: One site ID covers two subnets

- **WHEN** two via prefixes share a site ID and decode to different IPv4
  prefixes
- **THEN** lint reports one advice finding that names both routes and asks
  to confirm they are the same site

#### Scenario: Different site IDs are quiet

- **WHEN** two via prefixes have different site IDs
- **THEN** lint reports no `autoapprover-siteid-collision` finding

#### Scenario: Ordinary routes are quiet

- **WHEN** the route keys are ordinary IPv4 CIDRs
- **THEN** lint reports no `autoapprover-siteid-collision` finding

### Requirement: Unknown external tailnet aliases are errors

The lint capability SHALL report `external-tailnet-alias-unknown` at
`error` severity when a source or destination selector uses
`group://<alias>/<name>` or `tag://<alias>/<name>` and `<alias>` is not a
key of `externalTailnets`. The finding SHALL name the selector position.
A declared alias SHALL NOT produce that finding and SHALL NOT be reported
as an undefined local group or an unowned destination tag. A selector
that uses that syntax but does not parse SHALL produce the same finding.

#### Scenario: An unknown alias on a grant source is reported

- **WHEN** a grant source is `group://unknown-alias/eng` and
  `externalTailnets` has no `unknown-alias` key
- **THEN** lint reports one `external-tailnet-alias-unknown` error at
  `grants[0].src[0]`

#### Scenario: A declared alias is clean

- **WHEN** a grant source is `group://partner/eng` and `externalTailnets`
  declares `partner`
- **THEN** lint reports no `external-tailnet-alias-unknown` finding and no
  `undefined-reference` finding for that selector

#### Scenario: An auto-approver with a declared alias is not an undefined group

- **WHEN** `autoApprovers.exitNode` contains `group://partner/eng` and
  `externalTailnets` declares `partner`
- **THEN** lint reports no `undefined-reference` finding for that approver

#### Scenario: A cross-tailnet tag is not an unowned local tag

- **WHEN** a grant destination is `tag://unknown/device` and
  `externalTailnets` has no `unknown` key
- **THEN** lint reports `external-tailnet-alias-unknown` for that
  destination and does not report `dst-tag-no-owner`

### Requirement: Grants against a closed external tailnet warn

The lint capability SHALL report `external-tailnet-incoming-disabled` at
`warn` severity when a grant source or destination uses
`group://<alias>/<name>` or `tag://<alias>/<name>`, `<alias>` is declared
in `externalTailnets`, and `allowIncomingConnections` is not true. The
finding SHALL name the grant position and SHALL explain that the grant
and the alias flag must both be set. An alias that is not declared SHALL
NOT produce this finding.

#### Scenario: An omitted flag warns

- **WHEN** a grant source is `group://partner/eng` and `externalTailnets`
  declares `partner` without `allowIncomingConnections`
- **THEN** lint reports one `external-tailnet-incoming-disabled` warning
  at `grants[0].src[0]`

#### Scenario: An enabled flag is clean

- **WHEN** the same grant names an alias with
  `allowIncomingConnections` true
- **THEN** lint reports no `external-tailnet-incoming-disabled` finding

#### Scenario: An unknown alias is not also this warning

- **WHEN** a grant source is `group://missing/eng` and `externalTailnets`
  has no `missing` key
- **THEN** lint reports no `external-tailnet-incoming-disabled` finding

### Requirement: Invalid ipset members are errors

Lint SHALL report one `ipset-member-invalid` error when an ipset member
does not parse. The finding SHALL name the set and the member. It SHALL
NOT call the control plane.

#### Scenario: A bare name is not a member

- **WHEN** an ipset member is `gw` and a host named `gw` exists
- **THEN** lint reports one `ipset-member-invalid` error naming that set
  and `gw`

### Requirement: Missing ipset references are errors

Lint SHALL report one `ipset-reference-undefined` error when a parsed
`host:` or `ipset:` member names a definition that is absent.

#### Scenario: A missing host alias

- **WHEN** a member is `host:missing` and hosts has no `missing` entry
- **THEN** lint reports one `ipset-reference-undefined` error naming the
  member

#### Scenario: A missing ipset

- **WHEN** a member is `ipset:nope` and ipsets has no `ipset:nope` entry
- **THEN** lint reports one `ipset-reference-undefined` error naming the
  member

### Requirement: Ipset cycles are one error

Lint SHALL report one `ipset-reference-cycle` error when ipset references
form a cycle, and SHALL name the path. It SHALL use the existing reference
walk.

#### Scenario: Two sets refer to each other

- **WHEN** `ipset:p` contains `ipset:q` and `ipset:q` contains `ipset:p`
- **THEN** lint reports one `ipset-reference-cycle` error naming both sets

### Requirement: Host values must be addresses

Lint SHALL report one `host-not-address` error when a hosts value is
neither an address nor a prefix.

#### Scenario: A host value is a tag

- **WHEN** host `gw` is `tag:web`
- **THEN** lint reports one `host-not-address` error naming `gw` and
  `tag:web`

### Requirement: Valid ipsets stay quiet

Lint SHALL NOT report these four findings for members that parse and
resolve, including an address, a prefix, a defined `host:` alias, and an
`ipset:` reference that does not cycle. `ipset-mixed-operations` SHALL
still report a remove beside a member with no operation.

#### Scenario: A resolved set is quiet

- **WHEN** every ipset member parses and every reference exists
- **THEN** lint reports none of the four new findings

### Requirement: Posture references resolve against the postures map

The lint capability SHALL report an `undefined-reference` error when a
`srcPosture` entry in a grant or ACL entry, or a `defaultSrcPosture` entry,
names a posture absent from the policy's `postures` map. Reference names
SHALL be resolved with the same normalization the authoring commands use,
so a name `posture set` accepts is the name lint resolves.

#### Scenario: A grant's srcPosture names an undefined posture

- **WHEN** a grant carries `srcPosture: ["posture:missing"]` and `postures`
  defines no such posture
- **THEN** lint reports one `undefined-reference` error naming the grant's
  srcPosture position and `posture:missing`

#### Scenario: A defaultSrcPosture entry names an undefined posture

- **WHEN** the policy sets `defaultSrcPosture: ["posture:missing"]` and
  `postures` defines no such posture
- **THEN** lint reports one `undefined-reference` error naming the
  defaultSrcPosture position

### Requirement: Unused posture definitions are reported

The lint capability SHALL report an `unused-posture` info finding when a
posture is defined in `postures` but no `srcPosture` or
`defaultSrcPosture` references it. A reference from `defaultSrcPosture`
SHALL count as a use.

#### Scenario: An unreferenced posture is reported

- **WHEN** `postures` defines `posture:unused` and no `srcPosture` or
  `defaultSrcPosture` names it
- **THEN** lint reports one `unused-posture` info finding naming it

#### Scenario: A default-referenced posture is used

- **WHEN** `postures` defines `posture:linux` and only `defaultSrcPosture`
  references it
- **THEN** lint reports no `unused-posture` finding for it
