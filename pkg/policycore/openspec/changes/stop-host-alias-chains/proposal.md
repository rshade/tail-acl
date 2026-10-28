# Proposal

## Why

`ExpandAddressSelector` follows a `hosts` value into another host name, so
`{"a": "b", "b": "10.10.20.1"}` expands to `10.10.20.1` locally. The control
plane rejects that value with `ParseAddr("b"): unable to parse IP`. Offline
matchers then give a confident answer for a policy that cannot deploy.

## What Changes

- **BREAKING**: A `hosts` value that is not a literal address or prefix is
  returned unchanged. It is not followed to another host, tag, or ipset.
  A literal address or prefix is returned as that literal and is not looked
  up again as a host name.
- A host whose value is not a literal address or prefix is unmaterializable.
  `MatchesTri` reports `Unresolvable` and `Recognized` reports false, the
  same idea as an ipset that cannot be materialized. A literal host value
  stays decidable.
- A host cycle (`a` -> `b` -> `a`) cannot be a real policy once values must
  be literal. Expanding `"a"` returns `["b"]` and does not walk forever.
  The cycle guard may stay.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `selector`: host expansion no longer promises a transitive alias chain.
  A `hosts` value must be a literal address or prefix.
- `resolvable`: a non-literal host value is undecidable, not a confident
  non-match.

## Impact

`policycore/address.go` and `policycore/resolvable.go`. Callers that treated
a host alias chain as a CIDR, including `tail-acl check`, stop agreeing with
a policy the control plane rejects. Literal host values are unchanged.
`tail-acl` authors and lints the same rule in its own change of this slug.
