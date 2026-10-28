# Lint Delta

## ADDED Requirements

### Requirement: A non-literal hosts value is host-not-address

Lint SHALL report finding id `host-not-address` at error severity when a
`hosts` value is not a literal address or prefix. That includes a value that
names another host and a value that is a tag. The finding SHALL name the
host and the value. It SHALL NOT call the control plane.

#### Scenario: A host alias chain is an error

- **WHEN** `hosts` maps `a` to `b` and `b` to `10.10.20.1`
- **THEN** lint reports one `host-not-address` error naming `a` and `b`

#### Scenario: A host value that is a tag is an error

- **WHEN** `hosts` maps `gw` to `tag:web`
- **THEN** lint reports one `host-not-address` error naming `gw` and
  `tag:web`
