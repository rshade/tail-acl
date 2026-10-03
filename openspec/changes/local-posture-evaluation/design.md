# Design: local-posture-evaluation

## Context

The server semantics for posture gates were confirmed against the control
plane on 2026-10-02 (Features write-up 04): postures in one `srcPosture`
list are ORed, a posture's expressions are ANDed, an unset attribute fails
every comparison except `NOT SET`, and a test's `srcPostureAttrs` is
complete — the server supplies no default attributes. The parser and the
validation API landed with `posture-expression-validation`.

## Goals / Non-Goals

- Goal: `tail-acl test` on the reference policy passes all seven tests
  locally, exit 0, no server call.
- Goal: a posture outcome names the posture, expression, attribute, and
  outcome in the decision trace.
- Non-goal: evaluating a test *without* `srcPostureAttrs` as all-unset. The
  server does that, but it would turn today's indeterminate into a definite
  verdict for every existing posture test — a behavior change that is its
  own decision, not a side effect (user-confirmed 2026-10-02).
- Non-goal: version comparisons. `node:osVersion`/`node:tsVersion` with
  ordering operators use a server-side comparison function that is not
  documented closely enough to reproduce; they stay indeterminate until
  server fixtures pin them.

## Decisions

- **Presence, not length, for `srcPostureAttrs`.** The SDK type is a plain
  map, and `Load`'s decode keeps the empty-object/nil distinction, so an
  empty `{}` evaluates with a complete (all-unset) map — pinned by
  `TestEmptySrcPostureAttrsEvaluatesAsComplete`. Editability stays
  length-based; attribute-map merge semantics are Phase 5's decision.
- **Completeness is asserted, never inferred.** `posture.Attrs{Map,
  Complete}` mirrors `policycore`'s roster pattern. `test` asserts it for
  every `srcPostureAttrs` entry; `check` asserts it only under
  `--posture-attrs-complete`.
- **Partial mode does not judge a posture that reads an unsupplied
  attribute.** Without the completeness assertion a missing attribute is
  Unknown, and it clouds the whole posture — even beside a failing sibling
  rule — because the contract for a partial attribute set is that only
  fully-known postures are decided. That is the honesty `check` has always
  kept, and it is what makes the write-up's probe (`ip:country=KP` without
  the flag) indeterminate rather than a denial.
- **A decidably failed gate narrows like any other decidable non-match.**
  When every posture in the gate fails against supplied attributes the rule
  cannot apply, so the walker reports a clean non-match (deny evidence)
  instead of an indeterminate gate — the same narrowing the source and
  destination checks already apply.
- **Value typing mirrors expression literals.** `KEY=VALUE` parses bool,
  JSON number, double- or single-quoted string, else bare string, so
  `flag=true` is a boolean and `flag='true'` is a string. The helper lives
  in `internal/aclpolicy` so `test add --src-posture-attr` (Phase 5) shares
  it.

## Risks / Trade-offs

- Trace wording is additive: attr-less tests keep the exact legacy gate
  strings (a compatibility contract), and evaluated gates use new,
  deliberately distinct wording ("posture could not be evaluated locally").
- `scanRules` now lists an unparseable posture expression in the
  policy-scoped `skipped` array, so `-strict` rejects a policy carrying one.
  That is the correct reading of strict — the server rejects the policy too.
