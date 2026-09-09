# Wildcard Specification

## Purpose

Detect the literal `*` selector in a port-stripped selector list, for
callers such as tail-acl's overbroad-wildcard advisory, without treating any
autogroup as a wildcard.

## Requirements

### Requirement: Only the literal "*" selector counts as a wildcard

The wildcard capability SHALL report whether a selector list contains the
literal `*` selector after trimming surrounding whitespace from each entry.
It SHALL NOT treat `*` combined with a port suffix (e.g. `*:443`), nor any
autogroup — including `autogroup:tagged` and the role autogroups — as a
wildcard, leaving port-stripping and dynamic-membership evaluation to the
caller.

#### Scenario: A trimmed literal "*" is detected

- **WHEN** `ContainsLiteralWildcard` is given `["  *  "]`
- **THEN** it returns `true`

#### Scenario: A port-suffixed wildcard is not literal

- **WHEN** `ContainsLiteralWildcard` is given `["*:443"]`
- **THEN** it returns `false`, because port-stripping is the caller's
  responsibility

#### Scenario: autogroup:tagged is not treated as a wildcard

- **WHEN** `ContainsLiteralWildcard` is given `["autogroup:tagged"]`
- **THEN** it returns `false`, because only control-plane state can answer
  whether that autogroup names most of the fleet
