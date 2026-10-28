# Edit Delta

## ADDED Requirements

### Requirement: Removal sees external tailnet allow-lists

The edit capability's definition removal SHALL count a selector in
`externalTailnets[<alias>].allowExternalReferencesTo` as a reference. A
definition named only there SHALL be refused without `--force`, and the
referencing site SHALL be named
`externalTailnets[<alias>].allowExternalReferencesTo[<index>]`.

#### Scenario: A group exposed only to an external tailnet is refused

- **WHEN** `group:eng` is referenced only from
  `externalTailnets.partner.allowExternalReferencesTo` and
  `group remove` runs without `--force`
- **THEN** the command is refused and names
  `externalTailnets[partner].allowExternalReferencesTo[0]`

### Requirement: externalTailnets survives load and an unrelated edit

The edit capability SHALL load `externalTailnets` into the policy value the
pinned client models, and an unrelated comment-preserving edit SHALL leave a
hand-written comment inside that object byte-for-byte unchanged.

#### Scenario: A comment inside externalTailnets survives a grant edit

- **WHEN** a policy file contains a comment inside `externalTailnets` and an
  unrelated grant is appended with the comment-preserving patch
- **THEN** the comment is still present with the same bytes, and loading the
  file still yields the declared external tailnet
