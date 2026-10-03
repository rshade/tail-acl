# Design: posture-expression-validation

## Context

The posture expression grammar exists only on the control plane: the pinned
`tailscale.com` SDK has a `posture` package, but it collects serial numbers
and hardware addresses, not expressions. Every piece of the grammar and its
vocabularies is therefore an editorial reading of observed server behavior
(AX convention 13, Tier 2), and each reading needs a guard. The grammar,
operator list, bare-form rule, and `ip:country` vocabulary were all captured
from live server errors on 2026-10-02 (Features write-up 03).

## Goals / Non-Goals

- Goal: one parser and one validation vocabulary shared by `tail-acl` and
  `tailnet-audit`.
- Goal: offline validation that mirrors the server's reject messages closely
  enough that a finding names the same fix `validate` would.
- Non-goal: evaluating postures locally in `tail-acl`'s `test`/`check` (that
  is `local-posture-evaluation`). The unset-attribute semantics `tail-acl`
  will need there are deliberately not changed here: the Kleene composition
  and negated-comparison-is-Unknown behavior stay exactly as `tailnet-audit`
  has them.
- Non-goal: a complete known-attribute table. It is seeded (node:os,
  node:osVersion, node:tsVersion, node:app, ip:country) and grows by hand.

## Decisions

- **Move, don't fork.** The parser in `tailnet-audit/internal/audit/posture`
  is stdlib-only with a thorough test suite; moving it preserves both and
  puts the grammar where the repo's sharing rule wants it.
- **`ip:` attributes the capture cannot carry are Unknown, never absent.**
  The devices listing carries no GeoIP fact, so an unresolvable `ip:country`
  is missing data; reporting it as unset would claim a device fails a
  posture it may satisfy. Same rule as `node:` attributes the listing omits.
- **One error/warning split, encoded on the kind.** `ErrorLevel()` on
  `DiagnosticKind` is the single place the two callers' strictness comes
  from: unparseable and out-of-vocabulary values are errors everywhere;
  unknown attributes warn everywhere. Callers never re-derive the split.
- **The bare form on a known non-boolean attribute is unparseable.** The
  server reads a bare attribute as an implicit `== true` and rejects it for
  built-in string/version attributes with a message captured verbatim. On
  `custom:` or unknown attributes the bare form stays unchecked — the table
  is not authoritative enough to condemn them.
- **The fixture is the source of truth for countries.** The package
  vocabulary is built from the embedded fixture; the hand-written guard pins
  the two against each other (250 codes, `XK` present, `ZZ` absent — the
  write-up's `ZZ` claim did not reproduce live), and a `live_verify` test
  re-derives the list from a server error.

## Risks / Trade-offs

- The known-attribute table and the country list both go stale. That is why
  unknown attributes are warnings, why the country check is pinned to a
  captured fixture rather than a stock ISO table, and why the `live_verify`
  test exists. A stale country list produces a false *error*, which is the
  deliberate direction: the server rejects the policy too, and the fix
  (recapture) is one probe.
