# Design

## Context

Issue #275 was written when `tailscale.ACL` had no `externalTailnets` field
and asked for a sibling on `aclpolicy.Policy`, plus a new parameter on
`collectReferences`. Client v2.11.0, already pinned, models
`ExternalTailnets map[string]ExternalTailnet` with
`AllowExternalReferencesTo`. `Load` therefore accepts the key today.
`collectReferences` already receives `*tailscale.ACL`, and
`DefinitionReferences` already receives `*Policy`, which embeds that ACL.

What neither walk reads is `AllowExternalReferencesTo`. That is the #201
failure mode: lint says the group is unused, and `group remove` deletes it
at exit 0 with no `--force`.

## Goals / Non-Goals

**Goals:**

- Both walks see `allowExternalReferencesTo` in the same change.
- The unused-definition trace names the new field, and its golden is
  regenerated from the test.
- A regression locks comment preservation and load of the field.

**Non-Goals:**

- Authoring commands for `externalTailnets`.
- Setting `policycore.Policy.HaveExternalTailnets`. Check and test keep
  reporting cross-tailnet selectors as unsettled.
- A sibling `Policy.ExternalTailnets`. It would shadow the promoted field
  and hide it from `encoding/json`.

## Decisions

### Walk the promoted field; do not add a parameter

`collectReferences(policy *tailscale.ACL, sshRules, sshTests)` can read
`policy.ExternalTailnets` directly. Threading a fourth argument would
repeat a field the ACL already carries, which is the growth the issue
warned against. `DefinitionReferences` reads the same map through `*Policy`.

A helper `addExternalTailnetReferences` keeps the set-building walk next
to the other `add*References` helpers. The locator walk stays inside
`DefinitionReferences`, because only that function records positions.

### Locator shape

`externalTailnets[<alias>].allowExternalReferencesTo[<index>]`, with aliases
visited in sorted order so the reported slice is stable. Selectors are
compared the same way other non-destination references are: trimmed, not
host-normalized.

### Comment regression

Unrelated edits already go through `hujsonedit`, which does not rewrite
untouched objects. The test still has to fail when load rejects the
document or a rewrite drops the comment. On this pin, load accepts the
field, so the test passes once the file is modeled — which it is — and
locks the contract for the next pin.

## Risks / Trade-offs

- The unused-definition trace string is golden-tested. The only intended
  golden change is that string.
- A selector in the allow-list that is not a group or tag still counts as a
  reference, matching every other selector walk. Removal of a host named
  only there is refused. That is safer than the previous silent delete.

## Migration Plan

No data migration. Operators whose lint output named a group that exists
only in `allowExternalReferencesTo` stop seeing `unused-group` for it.

## Open Questions

None.
