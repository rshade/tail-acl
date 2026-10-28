# Ipcalc Spec Delta

## MODIFIED Requirements

### Requirement: IPv4 block facts account for the /31 and /32 special cases

The ipcalc capability SHALL report a prefix's masked network address,
broadcast address when applicable, usable host range, and usable-host count.
For IPv4, a `/30` or shorter SHALL exclude the network and broadcast
addresses from the usable range. An IPv4 `/31` (RFC 3021 point-to-point)
SHALL reserve neither address and a `/32` SHALL use its single address as the
whole usable range; neither SHALL report a broadcast address.

For IPv6, every address in the prefix SHALL be usable and no prefix SHALL
report a broadcast address. Usable-host counts SHALL be returned exactly as a
`*big.Int`, including counts larger than `uint64`. Host bits SHALL be masked
off before facts are computed for either address family. An invalid
`netip.Prefix` SHALL return a plain error distinct from valid prefix results.

#### Scenario: A /31 point-to-point link has no broadcast and two usable hosts

- **WHEN** `Info` is called on `10.0.0.0/31`
- **THEN** it reports no broadcast address, `FirstUsable=10.0.0.0`,
  `LastUsable=10.0.0.1`, and `UsableHosts=2`

#### Scenario: An IPv6 /64 reports every address as usable

- **WHEN** `Info` is called on `2001:db8:1::42/64`
- **THEN** it reports network `2001:db8:1::`, no broadcast address,
  `FirstUsable=2001:db8:1::`,
  `LastUsable=2001:db8:1:0:ffff:ffff:ffff:ffff`, and
  `UsableHosts=18446744073709551616`

#### Scenario: An IPv6 host route has one usable host

- **WHEN** `Info` is called on `2001:db8::1/128`
- **THEN** it reports network, first usable, and last usable as `2001:db8::1`,
  no broadcast address, and `UsableHosts=1`

#### Scenario: An invalid prefix is rejected

- **WHEN** `Info` is given an invalid `netip.Prefix`
- **THEN** it returns a plain error

#### Scenario: A non-IPv4 or invalid prefix is rejected

- **WHEN** `Info` is given an invalid `netip.Prefix`
- **THEN** it returns a plain error; native IPv6 is no longer rejected and
  instead follows the IPv6 block-fact behavior above
