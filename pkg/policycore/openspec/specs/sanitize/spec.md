# Sanitize Specification

## Purpose

Own the repository-wide output-sanitization contract — level parsing and
precedence, pseudonym allocation, exact-value text replacement, timestamp
quantization, and envelope metadata — independent of any tool's report
structs, so every CLI in this repository sanitizes identically.

## Requirements

### Requirement: A non-off environment level overrides an explicit flag

The sanitize capability SHALL resolve the effective level from
`TAILSCALE_SANITIZE` and a flag value, where a non-off environment value
takes precedence over any flag value and `TAILSCALE_SANITIZE=off` never
weakens an explicit flag. An unrecognized value from either source SHALL be
rejected as an error before precedence is applied. `Resolution.Notice`
SHALL produce a non-empty, identity-free stderr line only when the
environment instruction was active, and SHALL name the flag value it
overrode when the two differ.

#### Scenario: Environment overrides an explicit --sanitize=off

- **WHEN** `Resolve("identity", "off", true)` is called
- **THEN** it returns a resolution at `identity` with `EnvironmentActive` and
  `OverrodeFlag` both true, and `Notice` reports that the environment value
  overrode `off`

#### Scenario: An off environment value does not weaken an explicit flag

- **WHEN** `Resolve("off", "strict", true)` is called
- **THEN** it returns a resolution at `strict` with `EnvironmentActive`
  false, and `Notice` returns an empty string

### Requirement: Pseudonym never retains state; Value registers for later text replacement

`Sanitizer.Pseudonym(kind, value)` SHALL return a stable placeholder derived
from the sanitizer's key, its tool/scope/tailnet binding, and the (kind,
value) pair, without adding any entry to the sanitizer's retained state, no
matter how many distinct values are pseudonymized. `Sanitizer.Value(kind, value)` SHALL return the
same placeholder Pseudonym would for the first kind a literal is registered
under, and SHALL additionally register the value so a later `Text` call
replaces it; a value pseudonymized only through `Pseudonym` SHALL NOT be
replaced by a later `Text` call.

#### Scenario: Pseudonym stays O(1) in retained state across many distinct values

- **WHEN** `Pseudonym` is called with 10,000 distinct values on one
  sanitizer
- **THEN** the sanitizer's internal value-to-placeholder map and original-value
  list both remain empty afterward

#### Scenario: A value known only through Pseudonym is not found by Text

- **WHEN** a value is pseudonymized with `Pseudonym` but never passed to
  `Value`, and `Text` is then called on prose containing that value
- **THEN** the value passes through `Text` unchanged, because `Pseudonym`
  registered nothing to replace

### Requirement: Text replacement is case-insensitive, token-boundary-safe, and longest-match-first

`Sanitizer.Text` SHALL replace every value already registered through
`Value`, scanning left to right, matching ASCII case-insensitively, and
requiring a non-token-character boundary on both sides of a match so a
registered value that is also a substring of a longer word is left alone.
When two registered values tie at the same starting position, the longer
one SHALL win, and a registered value equal to another placeholder's prefix
SHALL NOT corrupt an already-inserted placeholder.

#### Scenario: A short delimited identity is replaced without corrupting an adjacent token

- **WHEN** `"0"` is registered and `Text("10 devices include id 0; code x0
  stays")` is called
- **THEN** only the delimited `0` is replaced; `"10"` and `"x0"` are left
  untouched

#### Scenario: Case differs between registration and the scanned text

- **WHEN** a hostname is registered in its original mixed case and `Text` is
  called on prose containing it in a different case
- **THEN** the differently-cased occurrence is still replaced by the
  registered placeholder

### Requirement: Strict level quantizes timestamps to a UTC calendar day

`Sanitizer.Time` SHALL return its input unchanged at every level except
`strict`, and at `strict` SHALL convert to UTC and truncate to the start of
that UTC calendar day, removing an exact activity fingerprint while
preserving day-granularity ordering.

#### Scenario: A strict sanitizer truncates a zoned timestamp to its UTC day

- **WHEN** `Time` is called at `strict` on `2026-08-17T17:23:11-05:00`
- **THEN** it returns `2026-08-17T00:00:00Z`

### Requirement: Metadata comparability requires a shared keyed domain

`Metadata.Comparable` SHALL report two metadata values comparable only when
both are active, both use the keyed HMAC scheme with a non-empty key
identifier, and every field of both values is equal; two inactive metadata
values SHALL be considered comparable to each other, and an ephemeral
(unkeyed) sanitizer's metadata SHALL never be comparable to any other
metadata, including another ephemeral one from the same run.

#### Scenario: Two ephemeral sanitizers are never comparable

- **WHEN** two sanitizers are each created with a fresh random key and their
  `Metadata()` values are compared with `Comparable`
- **THEN** it returns `false`, because artifact-scoped metadata carries no
  shared key identifier

### Requirement: AssertNoIdentityLeaks scans output as a plain substring, ignoring token boundaries

`sanitizetest.AssertNoIdentityLeaks` SHALL report every identity from a
non-empty input set found anywhere in rendered output, matching ASCII
case-insensitively as a plain substring rather than applying `Sanitizer.Text`'s
token-boundary rule, and SHALL fail loudly rather than passing vacuously when
the identity set or any of its entries is empty.

#### Scenario: An identity embedded inside a larger token is still reported

- **WHEN** rendered output contains `"pEMBED-215q"` and `"EMBED-215"` is in
  the identity set
- **THEN** `AssertNoIdentityLeaks` reports the leak, even though no token
  boundary surrounds it in the output
