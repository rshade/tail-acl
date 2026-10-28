# Design

## Context

`Sanitizer.Text` replaces only values already passed to `Value`.
`registerResultIdentities` registers the file path, tailnet, etag, check
selectors, findings, and — since `external-tailnet` — `EditedAlias`. The
mutation runners in this change set `File` and put the edited name only in
`Message`. `registerSelector` already applies the level split: a login,
hostname, IP, or CIDR is registered at `identity`; a `group:`, `tag:`,
`ipset:`, or `posture:` name is registered only at `strict`. See
proposal.md for why that gap matters.

## Goals / Non-Goals

**Goals:**

- One internal list of edited values, each tagged with how it is registered.
- Register that list inside `registerResultIdentities`, before `Message` is
  rewritten.
- Keep `external-tailnet` on that list and delete `EditedAlias`.

**Non-Goals:**

- Sanitizing stderr, including the posture expression warning.
- Sanitizing `--comment` text.
- Changing `pull`, `upload`, or `plan` messages.
- Reworking `sanitizeOrdinarySelector`.
- Serializing the new field or editing `schema.golden.json`.

## Decisions

### One slice replaces `EditedAlias`

`result.Edited` is `[]editedValue` with `json:"-"`, same exclusion as
`EditedAlias` and `LintSeverityExplicit`. Each element is a value plus how
to register it: through `registerSelector`, as `hostname`, or as `alias`.
An empty selector kind would force every caller to re-implement the level
split. A single string field cannot say "this bare host alias is a
hostname even if it parses as an address."

Alternative considered: keep `EditedAlias` and add parallel fields per
kind. That is a second mechanism, which is what left these commands out of
the external-tailnet fix.

### What each command records

The value recorded is the literal embedded in `Message`, not the display
wrapper.

- `group` and `ipset` add/remove record the definition name, via
  `registerSelector`. Members are not in the message.
- `tag-owner add` records the owner and the tag, both via
  `registerSelector`, including the already-owns path.
- `host set` records the alias as `hostname` and the address via
  `registerSelector`, including the already-set path.
- `posture set` and `remove` record the posture name via
  `registerSelector`, including already-set and not-present.
- `auto-approver` records `edit.Route` (the CIDR the message names) via
  `registerSelector`. It does not record the `"route "` prefix. An
  exit-node edit has an empty route and records nothing.
- `external-tailnet add` and `remove` record the alias as `alias`.

Registration of a prefixed operational name at `identity` is a no-op
inside `registerSelector`, so those names stay in the message without a
separate level check at the call site.

### Field guard

`TestSanitizedOutputTypesRequireExplicitFieldDecisions` lists every
exported `result` field. `Edited` replaces `EditedAlias` in that list.
`sanitizeResultEnvelope` does not copy the slice into the rebuilt
envelope; it only registers the values first.

## Risks / Trade-offs

- A new mutation message that names an identity without appending `Edited`
  leaks again. → The table test covers the commands in the evidence set,
  both levels, both formats, and the changed and no-op paths. The field
  guard does not catch a forgotten append.
- A host alias that is also a substring of the path or another identity
  could be rewritten inside that longer value. → `Text` already prefers
  the longer registered value and requires a token boundary. The file path
  is registered first, as it is today.
- `exitNode` and approver selectors are not in these messages, so they are
  not registered. A later wording change that prints them would leak until
  the runner records them.

## Migration Plan

No operator migration. Sanitization off is byte-compatible for these
commands. Rollback is reverting the registration; unsanitized files on
disk are untouched.

## Open Questions

None.
