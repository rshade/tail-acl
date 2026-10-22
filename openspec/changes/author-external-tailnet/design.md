# Design

## Context

Alias entries are objects, closer to `host set` than to `group add`.
Removal must see `group://` and `tag://` selectors, which do not compare
equal to the alias string `DefinitionReferences` matches.

## Goals / Non-Goals

**Goals:**

- Idempotent add for an identical alias, external ID, incoming flag, and
  allow-list.
- Refuse removal while any selector position the alias-unknown lint reads
  still names the alias. Grants are the case the issue names; ACL, SSH,
  tests, and auto-approvers are included so removal cannot create the
  finding it exists to avoid.
- List in both formats. Human text is the message. JSON adds
  `external_tailnets`.

**Non-Goals:**

- `grant add` accepting `group://` selectors.
- Checking `externalID` against a live tailnet.

## Decisions

`--allow-incoming` absent and an explicit false decode to the same bool.
A repeat with the same arguments does not rewrite an explicit false.

The allow-list accepts local `group:` and `tag:` selectors only. Duplicates
collapse in argument order.

## Risks / Trade-offs

- `-schema` gains three commands. The golden diff is those entries.

## Migration Plan

Existing files are unchanged until an operator runs a command.

## Open Questions

None.
