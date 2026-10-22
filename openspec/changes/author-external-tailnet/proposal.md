# Proposal

## Why

`externalTailnets` is the only definitional section without a typed edit.
Hand-editing it drops the comment preservation the other authoring
commands keep.

## What Changes

- `external-tailnet add` writes one alias. The same arguments again are a
  no-op.
- `external-tailnet remove` refuses an alias a selector still names, unless
  `--force` is set.
- `external-tailnet list` prints the section in human text and in the JSON
  envelope.
- `-schema` and `--help` list the three commands.

## Capabilities

### New Capabilities

- `external-tailnet-authoring`: add, remove, and list `externalTailnets`
  entries.

### Modified Capabilities

<!-- None. -->

## Impact

- New commands and one JSON field, `external_tailnets`, on the list
  envelope. `policycore` is unchanged.
