# Alpha Specification

## Purpose

Hand-model a Tailscale feature that is alpha or unreleased in the pinned
`tailscale.com/client/tailscale/v2` SDK — a validated feature inventory, the
declarative node-sharing selector grammar, and live-verification plumbing —
each carrying a migration tripwire so a hand-modeled type is never left
behind once the pinned SDK grows real support.

## Requirements

### Requirement: A registered feature must be complete, valid, and unique

`Registry.Register` SHALL reject a `Feature` with an empty `Name`, an empty
`DocURL`, a zero `ModeledDate`, an unrecognized `Stage`, or a `Name` already
registered in that registry. `Registry.List` SHALL return every registered
feature sorted by `Name`, independent of registration order.

#### Scenario: An unknown stage is rejected

- **WHEN** `Register` is called with `Stage: "released"`
- **THEN** it returns an error naming the unknown stage and does not add the
  feature

#### Scenario: A duplicate name is rejected without altering the first entry

- **WHEN** a feature named `"declarative-node-sharing"` is registered twice
- **THEN** the second `Register` call returns an error containing `already
  registered`, and `Lookup` still returns the first registration

### Requirement: Declarative node-sharing selectors require cross-tailnet group:// or tag:// syntax

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

### Requirement: The migration tripwire fails once the pinned SDK models externalTailnets

A dedicated test SHALL fail as soon as the pinned `tailscale.v2.ACL` type
carries any exported field whose JSON name is `externalTailnets` — under any
Go shape (map value, pointer, extra fields, embedding, an untagged field, or
an opaque `json.RawMessage`) and matched case-insensitively, the same way
`encoding/json` itself resolves field names — forcing a conscious decision to
migrate off `alpha.ExternalTailnets` rather than letting the hand-modeled
type silently diverge from a now-real SDK type.

#### Scenario: A synthetic SDK field is detected regardless of its shape

- **WHEN** the tripwire's detector is run against six synthetic ACL shapes
  that each carry an `externalTailnets`-named field through a different Go
  representation
- **THEN** every one is detected, and an unrelated field
  (`externalTailnetPolicy`) is not

### Requirement: A live verifier must name an already-registered feature

`VerifierRegistry.RegisterVerifier` SHALL reject a `nil` verify function, a
feature name not already present in the backing `Registry`, and a feature
name that already carries a registered verifier. `RunAll` SHALL run every
registered verifier against the given context and return one `VerifyResult`
per verifier, sorted by feature name, continuing past a failing verifier
rather than stopping at the first one.

#### Scenario: RunAll reports one failing and one passing verifier without stopping early

- **WHEN** two verifiers are registered, one whose live check succeeds and
  one whose live check reports a missing field, and `RunAll` is called
- **THEN** it returns both results sorted by feature name, the failing
  result carries a non-nil `Err`, and the passing result carries a nil `Err`
