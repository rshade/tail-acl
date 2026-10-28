# Proposal

## Why

`externalTailnets` is how an operator declares which groups and tags another
tailnet may name. The pinned client models the field, so load accepts it, but
neither reference walk reads `allowExternalReferencesTo`. Lint then reports a
live group as unused, and `group remove` deletes it without `--force`.

## What Changes

- Both reference walks count `externalTailnets[<alias>].allowExternalReferencesTo`
  selectors as uses of the named group or tag.
- The unused-definition decision trace names `externalTailnets` among the
  fields that were checked.
- A load/edit regression locks that a hand-written comment inside
  `externalTailnets` survives an unrelated patch, and that load populates
  the field the pinned client already models.
- `HaveExternalTailnets` stays false. Deciding cross-tailnet selectors is a
  later change.

## Capabilities

### New Capabilities

<!-- None. -->

### Modified Capabilities

- `lint`: an `allowExternalReferencesTo` selector counts as a use, and the
  unused-definition trace names `externalTailnets`.
- `edit`: `group remove` and `ipset` removal safety see the same selectors,
  and an unrelated edit leaves an `externalTailnets` comment in place.

## Impact

- `tail-acl` lint JSON traces for unused definitions change text. Finding
  ids, severities, and exit codes are unchanged except that a definition
  referenced only from `allowExternalReferencesTo` is no longer reported
  unused.
- No new command, flag, or schema version.
- `policycore` is not modified. The field is the promoted
  `tailscale.ACL.ExternalTailnets` from client v2.11.0, not a new sibling
  on `aclpolicy.Policy`.
