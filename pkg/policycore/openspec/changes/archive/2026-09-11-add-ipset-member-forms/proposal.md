# Proposal: add-ipset-member-forms

## Why

The control plane's ipset member grammar — CIDR or address, address range,
`host:` alias, nested `ipset:` reference, and ordered `add`/`remove`
operations with the rule that a `remove` makes every member explicit — is
implemented once in this repository, unexported inside
`tail-ipam/internal/policycheck`. `tail-acl` needs the same grammar to author
and lint ipsets, and writing a third parser is how two tools come to disagree
about one policy. `policycore` exists to hold exactly this kind of shared
policy vocabulary.

This is the `policycore` half of a change shared with `tail-acl` under the
slug `add-ipset-member-forms`.

## What Changes

- Add `ParseIPSetMember`, which classifies one raw member into its operation
  (`add`, `remove`, or implicit), its kind (prefix, range, host, ipset), and
  its canonical target, and `IPSetMember.String` which renders the canonical
  spelling.
- Add `ValidateIPSetOperations` and `IPSetImplicitMemberError`, the
  explicit-operation rule over a raw member list, working from the operation
  word alone so a linter can report the rule without requiring every target
  to parse.
- `ExpandAddressSelector` is deliberately unchanged in this change.

## Capabilities

### New Capabilities

- `ipset`: parse the control plane's ipset member grammar and enforce its
  explicit-operation rule.

### Modified Capabilities

<!-- None. -->

## Impact

- Additive exported API in the `policycore` root package; no existing
  function changes behavior.
- No new direct dependency: ranges are parsed with `net/netip` alone.
- `tail-ipam` keeps its own resolver for now; adopting the shared parser
  there is a later change.
