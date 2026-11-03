# External Selector Specification

## Purpose

Parse the declarative node-sharing selector grammar, `group://<alias>/<name>`
and `tag://<alias>/<name>`, so every tool in this repository agrees on what a
cross-tailnet selector is and rejects an authoring typo instead of letting it
become a silent non-match.

## Requirements

### Requirement: Cross-tailnet selectors require cross-tailnet group:// or tag:// syntax

`ParseExternalSelector` SHALL accept only `group://<alias>/<name>` and
`tag://<alias>/<name>`, rejecting a same-tailnet `group:`/`tag:` selector, a
selector with surrounding whitespace, a missing or whitespace-only alias, a
missing name, more than one `/`-separated segment after the alias, and a
name that itself carries a `group:` or `tag:` prefix (since `Kind` already
carries that distinction). An alias or name containing whitespace or any
non-printable character anywhere — not only at its edges — SHALL be rejected,
so an authoring typo cannot silently become a non-match.

#### Scenario: A same-tailnet selector is rejected

- **WHEN** `ParseExternalSelector("group:engineering")` is called
- **THEN** it returns an error requiring `group://` or `tag://` syntax

#### Scenario: An interior zero-width character in the alias is rejected

- **WHEN** `ParseExternalSelector` is given a selector with a zero-width
  space inside the alias
- **THEN** it returns an error reporting that the alias contains whitespace

#### Scenario: A name still carrying its prefix is rejected

- **WHEN** `ParseExternalSelector("group://partner/group:engineering")` is
  called
- **THEN** it returns an error stating the name must omit the `group:`
  prefix
