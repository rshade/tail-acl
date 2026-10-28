# Proposal

## Why

`--sanitize` rewrites a mutation command's `message` only for values the
command has already registered. `group`, `ipset`, `tag-owner`, `host`,
`posture`, and `auto-approver` put the edited name in that message and
register nothing but the file path, so hostnames, addresses, logins, and
route CIDRs survive `identity`, and operational names survive `strict`.

## What Changes

- Each of those mutation results records the identities embedded in its
  message, including the no-op ("already set", "not present") paths, and
  the sanitizer registers them before rewriting the message.
- `identity` still shows group, tag, ipset, and posture names. `strict`
  redacts those names. Hostnames, addresses, logins, and route CIDRs are
  redacted at both levels. The file path stays a path placeholder.
- `external-tailnet add` and `remove` use the same internal field as the
  other mutations. Their sanitized behavior does not change.
- The new field is not serialized. Unsanitized human and JSON output,
  including `message` wording, stays the same, and `schema.golden.json`
  does not change.

## Capabilities

### New Capabilities

<!-- None. -->

### Modified Capabilities

- `edit`: sanitized `message` text for group, ipset, tag-owner, host,
  posture, and auto-approver mutations redacts the identities that level
  is supposed to hide, on both the changed and no-op paths.

## Impact

- `tail-acl` command results only. No flag, schema, or envelope field.
- `policycore` is not modified. Registration reuses `registerSelector`
  and `Sanitizer.Value`.
- Stderr warnings and `--comment` text are unchanged.
