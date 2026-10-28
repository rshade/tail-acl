# Proposal: add-cross-tailnet-selector-resolution

## Why

`policycore` now recognizes cross-tailnet `group://<alias>/<name>` and
`tag://<alias>/<name>` selectors and reports them `Unresolvable` rather than
letting them fall through to a confident `NoMatch`. `tail-acl` is a consumer
of that matcher, so `check` and `test` change verdict for any policy that
uses the declarative node-sharing grammar — a user-visible change to a
compatibility contract, which is why it gets its own change rather than
riding along inside the library's.

This is the `tail-acl` half of a change shared with `policycore` and
`tailnet-audit` under the slug `add-cross-tailnet-selector-resolution`.

## What Changes

- `check` gains a fourth cause of `indeterminate`: a rule whose selector
  names another tailnet. It exits 10 and omits `allowed` for that case, as it
  already does for `via`, `srcPosture`, and an unresolvable role autogroup.
- `test` needs no requirement change: its `--indeterminate` requirement is
  already written cause-agnostically, as "an assertion that cannot be settled
  from the policy alone".
- The loader is updated to wrap its ACL in the new `policycore.Policy`
  container. It leaves `HaveExternalTailnets` false, because it does not yet
  parse the policy's `externalTailnets` declarations — so every cross-tailnet
  selector is reported `Unresolvable`, never as a decidable non-match.

## Capabilities

### New Capabilities

<!-- None. -->

### Modified Capabilities

- `check`: a cross-tailnet selector joins the causes of an `indeterminate`
  verdict.

## Impact

- **Compatibility**: for a policy using the cross-tailnet grammar, `check`
  moves from `"status": "failed"` / `"access": "deny"` / `"allowed": false` /
  exit 1 to `"status": "indeterminate"` / `"access": "indeterminate"` / no
  `allowed` field / exit 10. A policy that uses no `://` selector is
  bit-for-bit unaffected.
- `tail-acl/internal/aclpolicy/check.go` and `test.go` construction sites.
- No flag, command, or schema-version change.
