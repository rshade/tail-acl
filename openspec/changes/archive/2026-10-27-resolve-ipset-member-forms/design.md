# Design: resolve-ipset-member-forms

## Context

See proposal.md. `EvaluateReachability` and the `test` evaluator both build a
`policycore.Matcher` and decide every selector through `MatchesTri`; the
adapter `anySelectorMatches` reshapes `Unresolvable` into the gate that makes
a verdict `indeterminate`. Nothing in this module reads ipset members
directly, so the fix arrives entirely through `policycore`'s
`resolve-ipset-member-forms` change and this module's job is to pin the
verdicts it now produces.

## Goals / Non-Goals

**Goals:**

- Regression fixtures for exactly the cases #366 measured, so the resolver
  cannot regress without `tail-acl`'s own suite noticing.
- The indeterminate path is exercised for an unmaterializable set, proving
  the honest verdict reaches the CLI's exit code.
- The README stops promising a limitation that no longer exists.

**Non-Goals:**

- A CLI golden for `check` over these fixtures. The unit fixtures pin the
  verdict; the JSON envelope's shape does not change, and the existing check
  goldens already cover it.
- Linting an unmaterializable set. `lint` already reports dangling
  `host:`/`ipset:` selectors and mixed operations; reporting a set the
  resolver cannot materialize is a separate lint change.

## Decisions

- **Fixtures live in `reachability_test.go`, one per measured case.** The
  four #366 rows — removed address denied, kept address allowed, in-range
  address allowed, `host:` alias allowed — plus one indeterminate case for a
  set whose `host:` reference is undefined. Each is a `grantPolicy` case in
  the file's existing shape, not a new table, because each asserts a
  different verdict field.

- **The README describes the boundary, not the mechanism.** The paragraph
  that says `check`/`test` "do not yet apply" the forms is replaced with the
  forms a local verdict resolves and the one thing that makes it
  indeterminate. The "assumes the policy's references are valid" paragraph
  is narrowed: an undefined `ipset:` *selector* still matches nothing, but an
  undefined reference *inside* a defined ipset is now indeterminate.

- **The reachability golden's fixture is corrected, not the golden.**
  `testdata/reachability_policy.hujson` defined `ipset:corp` as
  `["corp-net"]`, a bare alias the control plane rejects, which the old
  resolver read only by following `Hosts` for every member. Under the new
  resolver that set is unmaterializable and three golden rows flip to
  `indeterminate`. The fixture now spells it `["host:corp-net"]`, the form
  the control plane accepts, and `reachability_report.golden.json` is
  byte-identical — which is the proof the verdicts did not move for a valid
  policy. Regenerating the golden instead would have enshrined a policy no
  tailnet can hold.

## Risks / Trade-offs

- [A test suite that relied on the false deny starts failing] → that suite
  was passing a `deny` assertion the control plane does not enforce; the
  README calls out the flip and the commit message names #366.
