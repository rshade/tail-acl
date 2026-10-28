# Design

## Context

`runHostSet` writes `args[1]` into `hosts` with no address check. The
control plane then fails `ParseAddr`. `lintHostAddresses` already emits
`host-not-address` for a value that is neither `ParsePrefix` nor
`ParseAddr`, and the catalog and schema golden already advertise that id.
What is missing is the authoring gate, and a lint scenario for an alias
chain rather than only `tag:web`.

PR #455 records `editedHostname(name)` and `editedSelector(address)` on the
`host set` result. That line stays on the success and no-change paths.

## Goals / Non-Goals

**Goals:**

- Reject a non-address before `WritePatch`. Exit 2. Name the value.
- Keep `100.64.0.10` and `10.1.0.0/16` successful.
- Lock lint coverage for both an alias chain and a tag value.

**Non-Goals:**

- Changing how `ExpandAddressSelector` walks hosts. That is policycore.
- A new lint id. `host-not-address` already exists.
- Regenerating the schema golden unless the catalog text changes.

## Decisions

1. **Validate with `ParsePrefix`, then `ParseAddr`.** A prefix is accepted
   by the first parse. Anything else uses the `ParseAddr` error in the
   message, which is the control-plane shape (`unable to parse IP`) and
   names the value.
2. **Return `usageError` before `loadForEdit`.** A bad address does not
   depend on the file, and the file is not opened for write. Comment-flag
   errors still win, because those flags are parsed first.
3. **Do not move the existing lint check.** It is already appended from
   `evaluateLint` beside `lintIPSetOperations`. Add the alias-chain case to
   the existing table test.

## Risks / Trade-offs

- `host set` of a value lint used to accept (`fe80::1%eth0`) still succeeds,
  because `ParseAddr` accepts a zone. That matches the existing lint
  predicate rather than the stricter ipset address parser, which rejects
  zones.

## Migration Plan

No migration. A file that already contains a bad host value is unchanged
until an operator sets a literal. `lint` already reports it.

## Open Questions

None.
