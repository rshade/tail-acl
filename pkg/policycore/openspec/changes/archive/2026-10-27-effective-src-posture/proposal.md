# Proposal: effective-src-posture

## Why

`defaultSrcPosture` gates every grant and ACL entry that does not set its own
`srcPosture`, and Tailscale documents a rule's own posture as *replacing* the
default, not adding to it. `tail-acl`'s local evaluator never reads the
default, so a policy gated entirely through it looks ungated locally and
`test`/`check` report accept for traffic the control plane drops — the
confident wrong verdict the three-state model exists to prevent.
`tailnet-audit`'s `collectGates` does read the default, so the two tools
currently disagree about one policy. The replacement rule belongs here, in
the shared library, so it is decided once.

This is the `policycore` half of a change shared with `tail-acl` under the
slug `effective-src-posture`. The defect and the server verdicts were
reproduced against the control plane on 2026-10-02 (Features write-up 01).

## What Changes

- Add a `posture` capability to `policycore` with one helper,
  `EffectiveSrcPosture(own, fallback []string) ([]string, bool)`: a rule's
  effective posture gate is its own `srcPosture` when non-empty, otherwise
  the policy's `defaultSrcPosture`. The boolean reports whether the result
  came from the default, so callers can say where a gate originated.

## Capabilities

### New Capabilities

- `posture`: source-posture semantics shared by the CLIs, starting with the
  effective-posture (replacement) rule.

### Modified Capabilities

<!-- None. -->

## Impact

- New file `policycore/posture.go` plus tests. No existing package changes.
- `tail-acl` carries the consumer half under the same slug.
- `tailnet-audit`'s `collectGates` models the default as an additive gate
  covering every device; that is a different question ("can this device
  satisfy a posture it is gated by?") and is deliberately not changed here.
  See design.md.
