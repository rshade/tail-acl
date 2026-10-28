# Lint Delta

## ADDED Requirements

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
