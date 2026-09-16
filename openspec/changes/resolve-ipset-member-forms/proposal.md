# Proposal: resolve-ipset-member-forms

## Why

`check` and `test` return false denials for any destination inside an ipset
that uses `add`/`remove` operations, an address range, or a `host:`
reference. Issue #366 measured it: with `ipset:trimmed = ["add ipset:base",
"remove 10.1.0.0/16"]` the control plane allows `tag:web -> 10.2.0.5:80` and
`check` reports `not reachable`. A `deny` assertion over such a set passes
for the wrong reason, and an `accept` assertion cannot pass at all. Since #365
`ipset add` authors every one of these forms, so the tool now writes sets its
own verdicts cannot read.

This is the `tail-acl` half of a change shared with `policycore` and
`tailnet-audit` under the slug `resolve-ipset-member-forms`: the resolver
lives in `policycore`, and this change covers the verdict surface it flips.

## What Changes

- `check` and `test` resolve every ipset member form: a set with `add` and
  `remove` operations matches what the operations leave, a range matches
  every address between its ends, and a `host:` reference matches the alias's
  address. The four measurements in #366 become reachability fixtures.
- A defined ipset whose members cannot be materialized — a member that does
  not parse, a `host:` or `ipset:` reference the policy does not define, a
  cycle, or an expansion past the resolver's limits — makes a verdict that
  reaches it `indeterminate` (exit 10 for `check`; `--indeterminate` policy
  for `test`) rather than `not reachable`. An undefined `ipset:` selector on
  a rule keeps matching nothing, as today.
- The README states which forms a local verdict resolves and what an
  unmaterializable set does to it, replacing the "do not yet apply" caveat,
  and names `autogroup:internet` inside an ipset — accepted by the control
  plane, not yet by the shared grammar — as the one form that stays
  indeterminate.

## Capabilities

### New Capabilities

<!-- None. -->

### Modified Capabilities

- `check`: verdicts resolve ipset operations, ranges, and `host:` references;
  an unmaterializable ipset is one more indeterminate fact.
- `test`: assertions over those sets evaluate against the materialized set.

## Impact

- **Compatibility**: a verdict flip on policies the control plane already
  enforces as written. Every `not reachable` over an `add`/`remove` set, a
  range, or a `host:` member was wrong; those become `reachable` when the
  address is in the effective set and stay `not reachable` when a `remove`
  withdrew it. No flag, output field, or exit code changes shape. The
  compatibility contract on `check`'s CLI and output is preserved.
- No code change in this module beyond tests and the README: the resolver is
  `policycore.ResolveIPSet`, reached through the `Matcher` `check`/`test`
  already build. Fixtures land in `internal/aclpolicy/reachability_test.go`.
