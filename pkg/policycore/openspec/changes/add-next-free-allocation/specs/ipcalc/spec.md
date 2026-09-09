# Ipcalc next-free delta

## ADDED Requirements

### Requirement: Select the first free child prefix without enumeration

The ipcalc capability SHALL select the lowest-address child prefix of a valid
pool at a requested width that does not overlap any valid same-family exclusion.
It SHALL search exclusion intervals and gaps directly, rather than materialize
all possible child prefixes before selecting one.

#### Scenario: A large sparse pool has an immediate free child

- **WHEN** a `/8` IPv4 pool is searched for a `/32` with a later exclusion
- **THEN** the first `/32` is returned without enumerating the pool's children

#### Scenario: Exclusions spanning a requested child are respected

- **WHEN** an exclusion contains the first requested child or is contained by
  it
- **THEN** the overlapping child is not selected

### Requirement: Free-child selection is family-safe and deterministic

The ipcalc capability SHALL mask valid prefixes before comparison, ignore
valid exclusions from another address family or outside the pool, and return
no result when the pool is invalid or the requested width is outside its
address-family bounds. For identical inputs it SHALL produce the same result.

#### Scenario: Mixed-family exclusions do not block an IPv4 result

- **WHEN** an IPv4 pool has only IPv6 exclusions
- **THEN** the first IPv4 child remains available

#### Scenario: Invalid target width has no result

- **WHEN** a target width is shorter than the pool or exceeds its address
  family width
- **THEN** free-child selection reports no result
