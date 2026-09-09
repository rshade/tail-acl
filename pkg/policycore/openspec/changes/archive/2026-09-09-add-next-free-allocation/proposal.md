# Add next-free allocation

## Why

Consumers that allocate a child subnet from a pool need a deterministic way
to locate the first non-overlapping block. Materializing every candidate is
not viable for the IPv6-scale follow-up, so the reusable primitive must search
address intervals directly from the start.

## What Changes

- Add `ipcalc.NextFree` to find the first usable child prefix inside a pool
  while excluding overlapping prefixes.
- Define IPv4 and IPv6-family validation, canonical masking, and deterministic
  treatment of malformed or irrelevant exclusions.
- Implement interval-gap search without enumerating child candidates.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `ipcalc`: Add deterministic free-child-prefix selection to the shared CIDR
  arithmetic capability.

## Impact

Adds a public API and tests in `policycore/ipcalc`. `tail-ipam` consumes the
API in the linked `add-next-free-allocation` OpenSpec change; the primitive
itself remains independent of registries, CLI output, and Tailscale APIs.
