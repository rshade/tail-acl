# Proposal: local-posture-evaluation

## Why

A posture-gated policy cannot be tested locally at all: `test` refuses the
whole file with exit 2 as soon as any test carries `srcPostureAttrs` — one
posture test hides the verdicts of every other test — and `check` has no way
to supply attributes, so any posture gate on the evaluation path is exit 10
(Features write-up 04). The local edit loop (`test --watch`) is unusable on
such a policy; every iteration needs a credentialed server round-trip.

The safety boundary's premise — posture resolves against control-plane state
the evaluator never sees — does not hold for a `tests` entry:
`srcPostureAttrs` writes the device's attributes into the file. The server
semantics were confirmed against the control plane on 2026-10-02: postures in
one `srcPosture` list are ORed, a posture's expressions are ANDed, an unset
attribute fails every comparison except `NOT SET`, and the server supplies
no default attributes for a test.

## What Changes

- `test` evaluates a test carrying a `srcPostureAttrs` key — even an empty
  object — against that map, treated as complete: what it omits is unset.
  The whole-file refusal is deleted. A test with no such key keeps the
  indeterminate gate with the exact legacy wording.
- `check` gains repeatable `--posture-attr KEY=VALUE` and
  `--posture-attrs-complete`. Values are typed (JSON bool/number/quoted
  string, single-quoted string, else bare string). Without the completeness
  flag, an attribute the gate reads but the query does not supply stays
  indeterminate.
- A rule whose posture gate decidably fails against the supplied attributes
  is a clean non-match (the traffic is denied by it), and the decision trace
  names the posture, expression, attribute, and outcome. An unevaluable gate
  — an unparseable expression (also listed in `skipped`), a version
  comparison (`node:osVersion`/`node:tsVersion` with ordering operators), or
  a needed-but-unsupplied attribute without completeness — stays
  indeterminate with wording distinct from the attr-less gate.
- Goldens are seeded from the write-up's reference policy, whose seven tests
  all pass on the control plane (confirmed 2026-10-02).

## Capabilities

### New Capabilities

<!-- None. -->

### Modified Capabilities

- `test`: posture gates evaluate against a test's `srcPostureAttrs`; the
  whole-file refusal is gone.
- `check`: posture gates evaluate against `--posture-attr` under
  `--posture-attrs-complete`; the unresolvable-fact requirement is restated
  for attribute-supplied evaluation.

## Impact

- `internal/aclpolicy/test.go` (gate evaluation in the rule walkers,
  per-test attribute plumbing, posture scanning in `scanRules`),
  `check.go` (`ReachabilityOptions`), and a new `postureattr.go`
  (`KEY=VALUE` parsing, shared with `test add` later).
- `cmd/tail-acl/commands.go` and `main.go` (new flags on `check`).
- New golden fixtures under `internal/aclpolicy/testdata/` (reference,
  flipped-expectation, mixed, empty-attrs policies and the reference
  report), the README's `test`/`check`/safety-boundary sections.
- The evaluator itself lives in `policycore/posture`
  (`posture-expression-validation` / its `EvaluatePosture` entry point);
  `tailnet-audit`'s Kleene behavior is untouched.
