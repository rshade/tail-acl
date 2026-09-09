# Proposal: add-ipv6-calc-aggregate

## Why

`ipcalc.Aggregate` is family-agnostic by construction but is specified and
tested only for IPv4, and its documentation forbids mixed-family input.
`tail-ipam calc aggregate` needs a stated IPv6 contract before it can stop
rejecting IPv6.

## What Changes

- Specify aggregation for IPv6 prefixes, including very wide prefixes and
  ULA space, with no algorithm change.
- Specify mixed-family input: a prefix never merges with, or is covered by,
  a prefix of the other family, and IPv4 results precede IPv6 results.
- Replace the one-family caller contract in the `Aggregate` documentation
  with the mixed-family contract.
- Add table-driven IPv6 and mixed-family test coverage.

## Capabilities

### New Capabilities

<!-- None. -->

### Modified Capabilities

- `ipcalc`: extend prefix aggregation from IPv4-only to IPv4 and IPv6 with
  a defined cross-family ordering.

## Impact

- `policycore/ipcalc/aggregate.go` changes only its documentation comment.
- `policycore/ipcalc/aggregate_test.go` gains IPv6 and mixed-family cases.
- No exported symbol, signature, or dependency changes, so the five modules
  that compile `policycore` through their local `replace` are unaffected.
- `tail-ipam` consumes the widened contract in its matching change.
