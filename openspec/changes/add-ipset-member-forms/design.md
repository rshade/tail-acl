# Design: add-ipset-member-forms

## Context

`AddDefinition` validates ipset members through `NormalizeIPSetCIDR` and
compares members for idempotence through the same function. The control
plane's ipset grammar is wider, and its one implementation in this repository
is unexported inside `tail-ipam/internal/policycheck`. `policycore`'s change
of the same slug adds the grammar as `ParseIPSetMember` and the
explicit-operation rule as `ValidateIPSetOperations`; this change consumes
them.

## Goals / Non-Goals

**Goals:**

- Author every member form the control plane accepts, validated against the
  policy in hand so a typo surfaces at authoring time rather than at upload.
- Keep `--cidr` byte-identical: same canonicalization, same idempotence, same
  error text.
- Flag the one shape the control plane rejects — a `remove` alongside an
  implicit member — both at authoring time and in `lint`.

**Non-Goals:**

- Teaching `check`/`test` to apply operations, ranges, or `host:` references.
  That is a `policycore` resolver change with its own verdict impact on
  `tailnet-audit` and belongs to a follow-up.
- Linting the member grammar itself (an unparseable target, an undefined
  nested reference). Only the mixing rule is added.
- Any change to `ipset remove`'s flags or output.

## Decisions

**`--member` and `--cidr` share one ordered list.** Each flag is a
`pflag.Value` that appends to the same slice, tagging whether the value came
from `--cidr`. Two independent lists would lose the interleaving order, and
order is the semantics of an operation list.

**`--cidr` values go through `NormalizeIPSetCIDR` unchanged.** The new parser
would accept a bare address that `--cidr` has always rejected, and the error
text for a rejected value is part of the compatibility contract, so the old
path is kept rather than emulated.

**Ranges and addresses are canonicalized, not kept as typed.** A range is
re-rendered from its parsed ends and an address from `netip.Addr.String`, so
`2001:DB8::1` and `2001:db8::1` cannot author two members. This is the
CIDR-masking decision extended to the new forms.

**A bare address and its `/32` are distinct members.** Both are valid control
plane spellings, and collapsing one into the other would rewrite what the
operator typed. Idempotence compares canonical strings only.

**Semantic checks live in `aclpolicy`, not `policycore`.** Host existence,
ipset existence, self-reference, and cycles need the policy; the grammar does
not. Keeping `policycore`'s addition to syntax and the operation rule keeps it
reusable by the resolver follow-up without dragging authoring policy along.

**Cycle detection resolves through existing definitions only.** The new
member's target is walked through `IPSets` looking for the set being edited;
members that do not parse are skipped, because a hand-written malformed
member is a lint concern, not a reason to refuse an unrelated add.

**The explicit-operation rule is evaluated on the resulting set.** Existing
members plus the members about to be added, in file order, so the first
implicit member named is the one an operator will find first in the file.
The rule runs after idempotence filtering, so re-running an already-applied
command stays a no-op even on a set the rule would reject.

**Reference walks follow ipset members.** `DefinitionReferences` and
`collectReferences` are kept in step by design; teaching both to look inside
ipset members (`ipset:` targets verbatim, `host:` targets by stripped alias,
either optionally under `add`/`remove`) is one addition rather than a drift.

**Lint severity is error.** The control plane rejects the mixed shape, which
is the same class as an undefined reference.

## Risks / Trade-offs

- **`unused-host`/`unused-ipset` disappear for nested-only uses** → this is
  the correct answer; the info finding was a false positive that
  `ipset remove` would have acted on.
- **`check` still ignores the new forms** → documented in the proposal and
  the README so an operator does not read a `not reachable` verdict as the
  control plane's answer for a set using them.
