# Proposal

## Why

`tsacl host set a b` writes a `hosts` value the control plane rejects
(`ParseAddr("b"): unable to parse IP`), and a policy that already contains
`{"a": "b"}` or `{"gw": "tag:web"}` used to expand as if the chain were a
real address. `lint` already has a `host-not-address` finding; authoring
must refuse the same values before the file changes.

## What Changes

- `host set` accepts only a literal IP address or CIDR prefix. Anything else
  exits 2, names the value as not an address, and leaves the file unchanged.
  `host set web 100.64.0.10` and `host set web 10.1.0.0/16` stay successful.
- `lint` reports `host-not-address` at error severity for a host alias chain
  and for a host whose value is a tag. The finding id, catalog entry, and
  check stay beside the other lint ids.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `edit`: `host set` validates the address before writing.
- `lint`: a non-literal `hosts` value, including an alias chain, is
  `host-not-address`.

## Impact

`tsacl host set` and `tsacl lint`. JSON stays on stdout; the rejection
is a usage error on stderr. Stacked on the mutation-message sanitizing
change: the success path still records the alias and the address as edited
values. Resolution behavior lives in the `policycore` change of this slug.
