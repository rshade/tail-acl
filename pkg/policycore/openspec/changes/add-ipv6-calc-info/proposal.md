# Proposal: add-ipv6-calc-info

## Why

`ipcalc.Info` deliberately rejects IPv6 even though callers need the same
block facts for IPv6 prefixes. IPv6 needs distinct semantics: it has no
broadcast address and its address counts exceed fixed-width integer types.

## What Changes

- Extend `ipcalc.Info` and `BlockInfo` to report masked IPv6 network facts.
- Model IPv6 as having no broadcast while making every address in the prefix
  usable, including `/127` and `/128`.
- Return exact arbitrary-precision IPv6 host counts using the existing
  `*big.Int` result field.
- Stop returning the IPv6-only sentinel while retaining it as a deprecated
  compatibility symbol for existing callers.

## Capabilities

### New Capabilities

<!-- None. -->

### Modified Capabilities

- `ipcalc`: extend block-fact calculation from IPv4-only to IPv4 and IPv6.

## Impact

- `ipcalc.Info` no longer returns `ErrIPv6NotSupported` for native IPv6.
- `policycore/ipcalc/info.go` and its table-driven tests gain IPv6 behavior.
- `tail-ipam` consumes the expanded result in its matching issue change.
