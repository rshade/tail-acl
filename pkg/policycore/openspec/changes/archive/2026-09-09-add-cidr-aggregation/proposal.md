# CIDR Aggregation Proposal

## Why

Operators need to summarize several IPv4 allocations into the smallest
equivalent CIDR set without rebuilding CIDR arithmetic in each caller.

## What Changes

- Add an IPv4 CIDR aggregation primitive to `policycore/ipcalc`.
- Collapse duplicate and covered prefixes as well as recursively merge
  adjacent equal-length sibling prefixes.
- Keep the primitive scoped to normalized, valid IPv4 input; callers retain
  responsibility for parsing and rejecting unsupported input.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `ipcalc`: aggregate a set of IPv4 prefixes into its deterministic minimal
  CIDR cover.

## Impact

Adds a public `policycore/ipcalc` API for tail-ipam's new aggregate command.
It has no network, registry, or Tailscale API dependency.
