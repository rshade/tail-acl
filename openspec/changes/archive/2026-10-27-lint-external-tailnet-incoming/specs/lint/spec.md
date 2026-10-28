# Lint Delta

## ADDED Requirements

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
