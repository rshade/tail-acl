# Proposal

## Why

`lint` accepts hand-written ipset members and host values that `validate`
rejects. The operator then sees an indeterminate check instead of a named
lint error.

## What Changes

- `ipset-member-invalid` when `ParseIPSetMember` rejects a member.
- `ipset-reference-undefined` when a `host:` or `ipset:` member is missing.
- `ipset-reference-cycle` when ipset references loop, using the existing
  reference walk.
- `host-not-address` when a hosts value is neither an address nor a prefix.
- Catalog, schema, and README entries for each. `ipset-mixed-operations`
  stays as it is.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `lint`: four new error finding classes for ipset members and host values.

## Impact

`lint` exits non-zero on policies the control plane would reject for these
shapes. Valid ipsets and the existing lint fixtures are unchanged.
