# Design: add-cross-tailnet-selector-resolution

## Context

See proposal.md — Why, and `policycore`'s change of the same slug for the
matcher-side decision table. `tail-acl` holds no decision of its own here: it
inherits `MatchesTri`'s verdict and maps `policycore.Unresolvable` onto the
`AccessIndeterminate` it already has.

## Goals / Non-Goals

**Goals:**

- Keep the exit-10 contract exact: an unprovable verdict is reported as
  unprovable, never resolved to a denial.

**Non-Goals:**

- Parsing `externalTailnets` out of policy HuJSON. That loader work is its
  own change; until it lands `HaveExternalTailnets` stays false and every
  cross-tailnet selector is `Unresolvable`.
- Any change to `--indeterminate`, `--strict`, or the JSON schema version.

## Decisions

**No mapping code is added.** `policyAllows` already routes
`policycore.Unresolvable` to `AccessIndeterminate`, and `check` already omits
`allowed` for that access. The new cause therefore reaches the correct output
through the path the role-autogroup case already takes; the change is the
loader's container wrap and nothing more.

**`HaveExternalTailnets` stays false, deliberately.** Setting it true without
parsing `externalTailnets` would tell the matcher an empty roster was read,
which turns every cross-tailnet alias into an undeclared one and restores the
confident `deny` this change exists to remove.

## Risks / Trade-offs

- **A policy using the alpha grammar changes verdict and exit code** → that
  is the intended correction, and it is confined to policies that use the
  grammar; `docs/reference/ax-conventions.md` reserves exit 10 for exactly
  this "cannot be determined" case.
- **Callers scripting on exit 1 may see 10** → documented here and in the
  commit's BREAKING CHANGE note; exit 10 already existed for three other
  causes, so no new exit code is introduced.
