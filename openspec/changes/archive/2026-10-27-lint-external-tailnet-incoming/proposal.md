# Proposal

## Why

A grant can name `group://alias/...` while that alias's
`allowIncomingConnections` is false or omitted. The grant is well formed
and still matches nothing, because Tailscale requires the flag on the
alias entry.

## What Changes

- Lint warns with `external-tailnet-incoming-disabled` when a grant source
  or destination names a declared alias whose
  `allowIncomingConnections` is not true.
- An alias that is not declared is left to `external-tailnet-alias-unknown`
  and is not also reported here.
- `-schema` lists the new check.

## Capabilities

### New Capabilities

<!-- None. -->

### Modified Capabilities

- `lint`: a grant against an alias that does not allow incoming
  connections is a warning.

## Impact

- New warning id. No command or flag. `policycore` is unchanged.
