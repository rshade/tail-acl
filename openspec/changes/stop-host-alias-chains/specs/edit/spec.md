# Edit Delta

## ADDED Requirements

### Requirement: host set accepts only a literal address or prefix

`host set` SHALL accept an ADDRESS only when it parses as an IP address or
a CIDR prefix. Any other value SHALL be rejected before the file is written.
The command SHALL exit 2, and the error SHALL name that value as not an
address. A successful or unchanged set SHALL still record the alias and the
address as edited values.

#### Scenario: An alias is rejected

- **WHEN** `host set a b` runs
- **THEN** the command exits 2, the error names `b` as not an address, and
  the file is unchanged

#### Scenario: A tag is rejected

- **WHEN** `host set gw tag:web` runs
- **THEN** the command exits 2, the error names `tag:web` as not an address,
  and the file is unchanged

#### Scenario: An IP address is still written

- **WHEN** `host set web 100.64.0.10` runs
- **THEN** the command succeeds and `hosts` maps `web` to `100.64.0.10`

#### Scenario: A CIDR prefix is still written

- **WHEN** `host set web 10.1.0.0/16` runs
- **THEN** the command succeeds and `hosts` maps `web` to `10.1.0.0/16`
