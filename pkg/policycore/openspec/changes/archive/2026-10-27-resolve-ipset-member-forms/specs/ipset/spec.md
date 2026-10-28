# Ipset Delta

## ADDED Requirements

### Requirement: An ipset materializes to the address space its members cover, applied in order

`ResolveIPSet` SHALL accept the name of an `IPSets` entry and the policy that
defines it and return the prefixes the set covers, as the minimal sorted
covering of the address space its members contribute. Members SHALL be
applied in list order: an implicit member and an `add` member contribute
their target's address space, and a `remove` member withdraws its target's
address space from whatever earlier members contributed, so a later `add`
re-contributes space an earlier `remove` withdrew. A target SHALL contribute
its prefix or address, every address of an inclusive range, the single
address or prefix its `host:` alias's `Hosts` entry holds, or the resolved
address space of a nested `ipset:` reference. A `remove` SHALL withdraw a
`host:` alias's address when that address lies inside the removed range,
exactly as it withdraws any other contributed address.

#### Scenario: A remove withdraws part of an added set

- **WHEN** `ipset:base` is `["10.0.0.0/8"]`, `ipset:trimmed` is
  `["add ipset:base", "remove 10.1.0.0/16"]`, and
  `ResolveIPSet("ipset:trimmed", policy)` is called
- **THEN** it returns prefixes that cover `10.2.0.5` and `10.0.0.1` and do
  not cover `10.1.0.5`

#### Scenario: A range expands to the addresses between its ends

- **WHEN** `ipset:rng` is `["10.5.0.1-10.5.0.9"]` and
  `ResolveIPSet("ipset:rng", policy)` is called
- **THEN** it returns prefixes that cover `10.5.0.1`, `10.5.0.4`, and
  `10.5.0.9` and do not cover `10.5.0.0` or `10.5.0.10`

#### Scenario: A host reference resolves through Hosts and is removable

- **WHEN** `Hosts` maps `gw` to `10.9.0.1`, `ipset:h` is `["host:gw"]`,
  `ipset:cut` is `["add host:gw", "remove 10.9.0.0/24"]`, and both are
  resolved
- **THEN** `ipset:h` covers `10.9.0.1` and `ipset:cut` covers nothing

#### Scenario: A later add re-contributes removed space

- **WHEN** `ipset:readded` is `["add 198.51.100.0/24",
  "remove 198.51.100.0/24", "add 198.51.100.2-198.51.100.3"]` and
  `ResolveIPSet("ipset:readded", policy)` is called
- **THEN** it returns exactly `[198.51.100.2/31]`

#### Scenario: The shared fixture resolves as tail-ipam resolves it

- **WHEN** the `operations` policy fixture `tail-ipam`'s `check-policy`
  tests commit is resolved set by set
- **THEN** `ipset:base` covers exactly `192.0.2.0/24`, `ipset:trimmed`
  exactly `192.0.2.0/25`, `ipset:empty` nothing, and `ipset:readded` exactly
  `198.51.100.2/31` — the address spaces `tail-ipam`'s golden report records

### Requirement: An ipset that cannot be materialized is an error, never a partial set

`ResolveIPSet` SHALL return an error, and no prefixes, when any member does
not parse under the ipset grammar (which includes `autogroup:internet`
until the grammar learns it), when the member list carries a `remove`
beside a member with no operation word (the explicit-operation rule
`ValidateIPSetOperations` enforces), when a `host:` alias is not defined in `Hosts`
or its `Hosts` value is not a literal address or prefix (a value naming
another alias is not followed: the control plane rejects such a `Hosts`
entry), when an `ipset:` reference names no `IPSets` entry, when an `ipset:`
reference is already on the current resolution path, when nesting exceeds
128 levels, or when the expansion exceeds 65536 prefixes. The error SHALL
name the set and the member position. A set that appears more than once in
one resolution through different paths SHALL be resolved once and reused,
and SHALL NOT be reported as a cycle.

#### Scenario: A bare alias is not a member

- **WHEN** `Hosts` maps `gw` to `10.9.0.1`, `ipset:x` is `["gw"]`, and
  `ResolveIPSet("ipset:x", policy)` is called
- **THEN** it returns an error naming member 1 and no prefixes

#### Scenario: An implicit member beside a remove is an error

- **WHEN** `ipset:mixed` is `["10.0.0.0/8", "remove 10.1.0.0/16"]` and
  `ResolveIPSet("ipset:mixed", policy)` is called
- **THEN** it returns an error naming `ipset:mixed` and both members, and no
  prefixes, because the control plane rejects the set rather than choosing
  an order for it

#### Scenario: An undefined host reference is an error

- **WHEN** `ipset:x` is `["host:missing"]` and no such host is defined
- **THEN** `ResolveIPSet("ipset:x", policy)` returns an error naming
  `host:missing`

#### Scenario: A host alias that names another alias is an error inside an ipset

- **WHEN** `Hosts` maps `a` to `b` and `b` to `10.10.20.1`, and `ipset:x` is
  `["host:a"]`
- **THEN** `ResolveIPSet("ipset:x", policy)` returns an error naming
  `host:a`, because `a`'s value is not an address or prefix

#### Scenario: A member the wire accepts but the grammar does not is an error

- **WHEN** `ipset:x` is `["add autogroup:internet", "remove 8.8.8.0/24"]`
- **THEN** `ResolveIPSet("ipset:x", policy)` returns an error naming member
  1, and no prefixes

#### Scenario: A cyclic ipset reference is an error and a diamond is not

- **WHEN** `ipset:a` is `["ipset:b"]` and `ipset:b` is `["ipset:a"]`, and
  separately `ipset:top` is `["ipset:left", "ipset:right"]` with both
  `ipset:left` and `ipset:right` being `["ipset:shared"]`
- **THEN** resolving `ipset:a` returns an error naming a cyclic reference,
  and resolving `ipset:top` returns `ipset:shared`'s prefixes without error
