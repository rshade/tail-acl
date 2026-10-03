# Lint Delta

## ADDED Requirements

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
