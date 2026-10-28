# Proposal: lint-autoapprover-route-overlap

## Why

`checkDuplicateMembers` only sees two `autoApprovers.routes` keys that are
the same raw string. Two spellings of one CIDR, or two different CIDRs that
share addresses, stay invisible to `lint` until an edit command happens to
refuse them. That is a static policy question, so it belongs in `tail-acl`
rather than in a live device audit.

## What Changes

- New warn finding `autoapprover-route-overlap` for a pair of
  `autoApprovers.routes` keys that mask to the same CIDR, or that overlap
  without being the same CIDR.
- A pair of 4via6 via prefixes is left to the sibling site-id check.
- The comparison uses `policycore/addrspace` and
  `NormalizeAutoApproverRoute`. This change does not add overlap math.

## Capabilities

### New Capabilities

<!-- None. -->

### Modified Capabilities

- `lint`: reports overlapping `autoApprovers.routes` CIDRs.

## Impact

- `internal/aclpolicy` lint catalog and `evaluateLint`.
- The `-schema` golden and the README lint table.
- No CLI flag and no control-plane call.
