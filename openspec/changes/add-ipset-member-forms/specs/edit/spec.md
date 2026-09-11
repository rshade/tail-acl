# Edit Spec Delta

## ADDED Requirements

### Requirement: ipset add accepts every control-plane member form

The edit capability's `ipset add` SHALL accept a repeatable `--member` whose
value is a CIDR prefix or bare address, an address range `A-B` whose ends
parse as addresses of one family with `A` not after `B`, `host:<alias>`,
`ipset:<name>`, or `add <member>` / `remove <member>` wrapping any of those.
CIDR, address, and range values SHALL be canonicalized; `host:` and `ipset:`
targets and the operation word SHALL be kept as written. `--cidr` SHALL
remain available and SHALL accept only the CIDR prefix form with the same
canonicalization and error text as before. The two flags MAY be combined and
members SHALL be appended in argument order. A member already present in its
canonical form SHALL NOT be appended again.

#### Scenario: A nested reference and a range are authored

- **WHEN** `ipset add --name ipset:x --member ipset:base --member 10.0.0.1-10.0.0.9`
  runs against a policy defining `ipset:base`
- **THEN** `ipsets["ipset:x"]` holds `["ipset:base", "10.0.0.1-10.0.0.9"]`
  and repeating the command reports `no_changes`

#### Scenario: --cidr still rejects a bare address

- **WHEN** `ipset add --name ipset:x --cidr 10.0.0.1` runs
- **THEN** the command exits 2 with `ipset member "10.0.0.1" is not a CIDR
  prefix: netip.ParsePrefix("10.0.0.1"): no '/'`, exactly as before

### Requirement: ipset add validates references against the policy

The edit capability SHALL reject a `--member` whose `host:` alias is not
defined in `hosts`, naming the alias; a `--member` whose `ipset:` target is
not defined in `ipsets`, naming the target; a `--member` that names the ipset
being edited; and a `--member` whose `ipset:` target reaches the ipset being
edited through existing definitions, naming the reference path. The file
SHALL be unchanged in every case.

#### Scenario: A missing host alias is named

- **WHEN** `ipset add --name ipset:x --member host:gw` runs against a policy
  whose `hosts` has no `gw`
- **THEN** the command exits 2 and the error names `gw` as not defined in
  hosts

#### Scenario: A cycle through an existing set is refused

- **WHEN** `ipsets` defines `ipset:a` as `["ipset:x"]` and
  `ipset add --name ipset:x --member ipset:a` runs
- **THEN** the command exits 2 and the error shows the path
  `ipset:x -> ipset:a -> ipset:x`

### Requirement: A remove operation requires every member to be explicit

The edit capability SHALL reject an `ipset add` whose resulting set — the
existing members followed by the members about to be added — contains a
`remove` operation alongside any member that is not an explicit `add` or
`remove` operation. The error SHALL name the first such implicit member and
the `add <member>` spelling to use, and the file SHALL be unchanged.

#### Scenario: Implicit members alongside a remove are rejected

- **WHEN** `ipset add --name ipset:x --member ipset:base --member host:gw
  --member 'add 10.0.0.0/8' --member 'remove 10.1.0.0/16'` runs
- **THEN** the command exits 2, names `ipset:base` as the member needing an
  explicit operation, and says to write it as `add ipset:base`

#### Scenario: An all-explicit set is written

- **WHEN** the same command runs with `add ipset:base` and `add host:gw`
- **THEN** the set is written with all four members in argument order

### Requirement: Remove sees references inside ipset members

The edit capability's `ipset remove` SHALL count an `ipset:` reference
inside another ipset's members — bare or under an `add`/`remove` operation —
as a reference, so such a definition is refused without `--force` and the
referencing site is named as `ipsets[<name>][<index>]`.

#### Scenario: A nested-only ipset is refused without --force

- **WHEN** `ipset:base` is referenced only as `add ipset:base` inside
  `ipset:x` and `ipset remove --name ipset:base` runs
- **THEN** the command is refused naming `ipsets[ipset:x][0]`
