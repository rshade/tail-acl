# Lint Delta

## ADDED Requirements

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
