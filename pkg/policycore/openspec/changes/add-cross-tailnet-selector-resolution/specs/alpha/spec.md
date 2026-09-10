# Alpha Spec Delta

## ADDED Requirements

### Requirement: Cross-tailnet selector recognition shares the parser's scheme prefixes

`LooksLikeExternalSelector` SHALL report whether a selector uses the
declarative node-sharing scheme syntax — a `group://` or `tag://` prefix —
independently of whether the rest of the selector is well-formed, so a
caller can route a malformed cross-tailnet reference to the cross-tailnet
vocabulary rather than treating it as an ordinary local selector. It SHALL
recognize exactly the prefixes `ParseExternalSelector` accepts, sharing one
definition of them, so recognition and parsing can never disagree about what
is a cross-tailnet selector. A same-tailnet `group:`/`tag:` selector, and any
other string, SHALL NOT be recognized.

#### Scenario: A malformed cross-tailnet selector is still recognized

- **WHEN** `LooksLikeExternalSelector("group://partner")` is called
- **THEN** it returns `true`, even though `ParseExternalSelector` rejects the
  same selector for a missing name

#### Scenario: A same-tailnet selector is not recognized

- **WHEN** `LooksLikeExternalSelector("group:engineering")` and
  `LooksLikeExternalSelector("tag:batch")` are called
- **THEN** both return `false`

#### Scenario: Every selector the parser accepts is recognized

- **WHEN** `LooksLikeExternalSelector` is called on
  `"group://partner/engineering"` and on `"tag://production/batch"`
- **THEN** both return `true`
