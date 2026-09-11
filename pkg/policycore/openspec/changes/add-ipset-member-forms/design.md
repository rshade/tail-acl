# Design: add-ipset-member-forms

## Context

See proposal.md. The reference grammar is `tail-ipam`'s
`parseOperations`/`target`/`literalPrefix`; this change lifts the syntax into
`policycore` and leaves resolution where it is.

## Goals / Non-Goals

**Goals:**

- One place that says what an ipset member may look like, with canonical
  rendering so authoring tools can compare members for idempotence.
- An operation-rule check that works on raw strings, because the rule is
  about the operation word and a lint pass must report it even for a member
  whose target is itself malformed.

**Non-Goals:**

- Resolving members to prefixes, applying operations, or changing
  `ExpandAddressSelector`. That is the resolver follow-up.
- Validating that a `host:` alias or `ipset:` name exists; that needs a
  policy and belongs to the caller.

## Decisions

- **Syntax only, no policy argument.** `ParseIPSetMember` takes a string and
  returns a value; existence and cycle checks are the caller's, so the parser
  is usable by a linter, an editor, and a future resolver alike.
- **Ranges are parsed with `net/netip`, not `netipx`.** Two addresses, no
  zones, one family, start not after end. `netipx` stays an indirect
  dependency.
- **Canonical target rendering.** A prefix is masked, an address and a
  range's ends are re-rendered from `netip.Addr.String`, and `host:`/`ipset:`
  targets are kept as written; the operation word is lowercase `add`/`remove`
  only. A bare address is not promoted to a `/32` or `/128`: both are valid
  control-plane spellings and the parser must not rewrite what an operator
  typed.
- **The operation split uses `strings.Fields`.** Exactly one field is an
  implicit member; exactly two with a first field of `add` or `remove` is an
  operation; anything else is rejected, including an unknown operation word
  and interior whitespace in a target. This is the `tail-ipam` rule.
- **`ValidateIPSetOperations` classifies by the operation word alone.** A
  member is explicit when it is exactly two fields led by `add` or `remove`;
  everything else counts as implicit. The error carries the first implicit
  member and the first `remove` seen so the message can name both.

## Risks / Trade-offs

- **Two grammars until `tail-ipam` adopts this one** → the parser mirrors
  `tail-ipam`'s accepted set exactly, and its tests pin the cases
  `tail-ipam`'s fixtures use, so the adoption is a mechanical swap.
