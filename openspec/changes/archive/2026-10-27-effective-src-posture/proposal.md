# Proposal: effective-src-posture

## Why

`tail-acl test` and `tail-acl check` gate a rule on its own `srcPosture`
only. A policy that gates everything through `defaultSrcPosture` looks
ungated locally: `check` reports `reachable` and `test` reports `PASS` for
traffic the control plane drops (reproduced against the server on
2026-10-02; Features write-up 01). That is the confident wrong verdict the
evaluator's three-state design exists to prevent.

This is the `tail-acl` half of a change shared with `policycore` under the
slug `effective-src-posture`; the replacement rule itself lands there as
`EffectiveSrcPosture`.

## What Changes

- The local evaluator gates each grant and ACL entry on the rule's
  *effective* posture: its own `srcPosture` when non-empty, otherwise the
  policy's `defaultSrcPosture`.
- A gate inherited from the default is reported as such — the decision text
  reads `uses unsupported srcPosture (from defaultSrcPosture)` — so a user
  looking at a rule with no `srcPosture` field can see why it is gated.
  Until posture expressions evaluate locally
  (`local-posture-evaluation`), the verdict stays `indeterminate` (exit 10
  for `check`; the `--indeterminate` ladder for `test`), which is the honest
  answer.
- **BREAKING (verdict correction):** policies using `defaultSrcPosture`
  change local verdicts from accept/pass to indeterminate. Policies without
  `defaultSrcPosture` are byte-for-byte unchanged in behavior.

## Capabilities

### New Capabilities

<!-- None. -->

### Modified Capabilities

- `check`: the posture gate reads the effective posture, not only the
  rule's own field, and names the origin of an inherited gate.
- `test`: same gating change for assertion evaluation.

## Impact

- `internal/aclpolicy/test.go` (`postureGate`, the grant and ACL gate
  sites), new golden fixtures seeded from the server-confirmed probes of
  Features/01 (grant form and `acls` form), README posture section.
- Golden fixtures whose evidence text includes the gate wording may gain
  the origin suffix where a default applies; no other wording changes.
