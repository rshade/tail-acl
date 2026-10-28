# Lint Delta

## ADDED Requirements

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
