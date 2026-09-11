# Proposal: add-ipset-member-forms

## Why

`ipset add` validates every member with `netip.ParsePrefix`, so the other
member forms the control plane accepts — nested `ipset:` references, `host:`
aliases, address ranges, and ordered `add`/`remove` operations — are rejected
with "is not a CIDR prefix". A policy that uses them cannot be authored
through `tail-acl`; in the 2026-09-10 full-network exercise 15 of 33 ipsets
had to be merged in by hand. `tail-ipam check-policy` already resolves every
form, so the two tools disagree about which policies are authorable.

This is the `tail-acl` half of a change shared with `policycore` under the
slug `add-ipset-member-forms`: the member grammar lives there so no third
parser is written.

## What Changes

- `ipset add` gains a repeatable `--member` flag accepting a CIDR or bare
  address, an address range `A-B`, `host:<alias>`, `ipset:<name>`, or
  `add <member>` / `remove <member>` wrapping any of those. `--cidr` stays and
  keeps its exact CIDR-only validation and error text. The two flags may be
  combined; members are appended in argument order.
- `--member` validates against the policy in hand: a `host:` alias must be
  defined in `hosts`, an `ipset:` reference must name an existing ipset other
  than the one being edited, and a reference that would close a cycle through
  the existing definitions is rejected naming the path.
- The explicit-operation rule: when the resulting set carries a `remove`
  operation, every member must be an explicit `add`/`remove`; otherwise the
  command fails naming the first implicit member and the `add <member>`
  spelling to use.
- `lint` gains `ipset-mixed-operations` (error) for a hand-written set that
  mixes implicit members with a `remove` operation.
- The unused-definition walk and the removal safety walk both follow
  `ipset:` and `host:` references inside ipset members, so a definition used
  only by another ipset is neither reported unused nor removed without
  `--force`.
- `-schema` and `--help` describe the member forms; the README documents
  them, the rule, and the lint check.

## Capabilities

### New Capabilities

<!-- None. -->

### Modified Capabilities

- `edit`: `ipset add` accepts every ipset member form and enforces the
  explicit-operation rule; `ipset remove` sees nested references.
- `lint`: new `ipset-mixed-operations` finding; nested ipset references count
  as uses.

## Impact

- **Compatibility**: additive. Every existing `ipset add --cidr` invocation
  produces the same file and the same error text. The `-schema` document
  changes the `ipset add` summary and usage and gains one `lint_findings`
  entry. A policy whose only reference to a definition is inside another
  ipset stops producing an `unused-*` info finding.
- `tail-acl/internal/aclpolicy/definitionedit.go`, `lint.go`,
  `cmd/tail-acl/commands.go`, `main.go`, the schema golden, and the README.
- `check` is unchanged: `policycore.ExpandAddressSelector` does not yet apply
  operations, ranges, or `host:` references, so a set authored with those
  forms is not resolved by `check` or `test`. That resolver change is a
  separate, shared-slug follow-up.
