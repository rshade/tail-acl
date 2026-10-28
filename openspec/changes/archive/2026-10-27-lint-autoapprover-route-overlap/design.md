# Design

## Context

`ACLAutoApprovers.Routes` is a map of CIDR strings. The editor already
masks a key with `NormalizeAutoApproverRoute` and refuses when several raw
keys name one prefix. Lint does not.

## Goals / Non-Goals

**Goals:**

- Warn when two keys mask to one CIDR.
- Warn when two distinct CIDRs overlap.
- Skip a pair when both keys are via prefixes (`IsViaPrefix`).
- Stay network-free and catalog the finding.

**Non-Goals:**

- Site-id collisions between via prefixes.
- Live device route advertisements.
- Ipset overlap.

## Decisions

One finding id covers both sub-cases. Evidence distinguishes a masked
duplicate from a partial overlap. Keys are compared after
`NormalizeAutoApproverRoute`. A key that does not parse is skipped, because
this check does not invent a second invalid-CIDR finding. A via prefix
beside an ordinary route is compared as written: `Overlaps` does not decode
the embedded IPv4, so a via prefix does not overlap `10.0.0.0/8`.

## Risks / Trade-offs

- `-schema` gains one catalog object. The golden diff is that object.

## Migration Plan

Existing policies are unchanged. `lint` may newly warn.

## Open Questions

None.
