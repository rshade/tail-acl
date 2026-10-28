# Design

## Context

`autoapprover-route-overlap` skips pairs where both keys are via prefixes.
Those pairs are this check. A site ID names a site, not one subnet, so the
same ID on two subnets is often correct.

## Goals / Non-Goals

**Goals:**

- One advice finding per site ID whose via routes decode to more than one
  IPv4 prefix.
- Name every route in that group, and ask the reader to confirm they are
  the same site.
- Ignore keys `IsViaPrefix` or `SiteID` reject.

**Non-Goals:**

- Treating the grouping as a warn or an error.
- Overlap between ordinary CIDRs.
- Live device advertisements.

## Decisions

Severity is `advice`, below `info`, so the finding is visible and does not
fail `lint`. `Value` is the site ID. The embedded IPv4 address comes from
`tsaddr.UnmapVia` after `IsViaPrefix` and `SiteID` accept the prefix. The
prefix length is the via length minus the via-range length and the IPv4
address length, which is what `MapVia` adds.

## Risks / Trade-offs

- `-schema` gains one catalog object.

## Migration Plan

Existing policies are unchanged. `lint` may newly print advice.

## Open Questions

None.
