# external-tailnet-authoring Specification

## Purpose

Author the `externalTailnets` section through typed edits that keep the
policy's comments, instead of hand-editing that section.

## Requirements

### Requirement: Adding an external tailnet is idempotent

`external-tailnet add` SHALL write `externalTailnets.<alias>` with the
given external ID, incoming flag, and allow-list. Repeating the command
with the same arguments SHALL leave the file unchanged and report no
changes. An unrelated comment in the file SHALL survive the first add.

#### Scenario: A second identical add does not rewrite the file

- **WHEN** `external-tailnet add partner --external-id tn-123` runs twice
- **THEN** the second run reports no changes and the file bytes match the
  first run

#### Scenario: A neighboring comment survives

- **WHEN** the file has a comment on another section and the operator adds
  an alias
- **THEN** that comment is still present and the alias reloads with the
  requested external ID

### Requirement: Removing a referenced alias needs force

`external-tailnet remove` SHALL refuse, without `--force`, when a grant,
ACL, SSH rule, test, or auto-approver selector uses
`group://<alias>/...` or `tag://<alias>/...`. The error SHALL name the
location. `--force` SHALL remove the alias anyway. A missing alias SHALL
be a no-op.

#### Scenario: A grant reference blocks removal

- **WHEN** a grant source is `group://partner/eng` and the operator removes
  `partner` without `--force`
- **THEN** the command fails, names `grants[0].src[0]`, and the alias
  remains

#### Scenario: Force removes a referenced alias

- **WHEN** the same remove runs with `--force`
- **THEN** the alias is gone

### Requirement: Listing emits human text and JSON

`external-tailnet list` SHALL print each alias for a human and SHALL
include an `external_tailnets` array in the JSON envelope. The array
SHALL be present, and empty, when the section is absent.

#### Scenario: JSON lists the alias

- **WHEN** the file declares `partner` and list runs with `-format json`
- **THEN** the envelope contains `external_tailnets` with that alias
