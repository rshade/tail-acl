# Proposal

## Why

A grant can name `group://alias/name` or `tag://alias/name` before that
alias exists in `externalTailnets`. Lint treats `group://` as an ordinary
`group:` and `tag://` as an ordinary destination tag, so the typo is either
mis-filed or missed.

## What Changes

- Lint reports `external-tailnet-alias-unknown` at error severity when a
  cross-tailnet selector's alias is not a key of `externalTailnets`, or the
  selector uses that syntax but does not parse.
- A selector whose alias is declared produces no finding from this check
  and is not also reported as an undefined local group or tag.
- `-schema` advertises the new check through `LintCatalog`.

## Capabilities

### New Capabilities

<!-- None. -->

### Modified Capabilities

- `lint`: unknown cross-tailnet aliases are an error, and a declared alias
  is not an undefined local reference.

## Impact

- New machine-readable finding id. Existing finding ids are unchanged.
- No command or flag. `policycore` is not modified; parsing reuses
  `policycore/alpha`.
