# Design: effective-src-posture

## Context

Two shipped tools read `defaultSrcPosture` differently: `tail-acl` ignores
it, `tailnet-audit` treats it as an additional gate over the whole
inventory. Tailscale's documentation describes replacement semantics: a
rule's own `srcPosture` replaces the tailnet-wide default for that rule.

## Goals / Non-Goals

- Goal: one shared, tested statement of the replacement rule.
- Goal: the origin (rule vs default) is available to callers so decision
  text can say where a gate came from.
- Non-goal: changing `tailnet-audit`'s `collectGates`. Its question is
  per-device posture coverage, where the additive reading may over-report a
  device reached only through rules with their own posture. Settling that
  needs coverage-fixture evidence and is scoped out (recorded in
  Features/01 as an open question).
- Non-goal: parsing or evaluating posture expressions (that is
  `posture-expression-validation` / `local-posture-evaluation`).

## Decisions

- **Replacement, not additive.** Documented Tailscale semantics; also the
  only reading under which "a rule with its own `srcPosture` ignores the
  default" holds.
- **Return the origin as a bool, not a string enum.** Two origins exist;
  a bool keeps the helper total and lets the caller compose its own prose.

## Risks / Trade-offs

- None behavioral for `policycore` itself: the helper is additive.
