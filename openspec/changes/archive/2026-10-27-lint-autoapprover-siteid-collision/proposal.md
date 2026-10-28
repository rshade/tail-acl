# Proposal: lint-autoapprover-siteid-collision

## Why

Several via prefixes can share one site ID because a site advertises more
than one subnet. The policy text cannot tell that ordinary case from two
sites that reused an ID. `lint` should surface the grouping for a person to
confirm, without calling it a defect.

## What Changes

- New advice finding `autoapprover-siteid-collision` when via-prefix
  `autoApprovers.routes` keys share a site ID and their IPv4 subnets differ.
- Different site IDs, and ordinary CIDRs, stay quiet.
- Site ID and via recognition come from `policycore/addrspace`. The
  embedded IPv4 address is the last four bytes of an accepted via prefix.

## Capabilities

### New Capabilities

<!-- None. -->

### Modified Capabilities

- `lint`: advises when one via site ID covers different subnets.

## Impact

- Lint catalog, `-schema`, and the README lint table.
- No CLI flag and no control-plane call. Advice does not change the lint
  exit code.
