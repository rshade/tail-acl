# Lint a policy and act on the findings

`lint` reports policy-hygiene problems that validation does not catch: a policy
can be valid and still carry grants that match nothing, destination tags no
node can own, or references to definitions that were renamed away.

This guide covers running the check, triaging what it reports, and turning the
result into a gate. The full finding table lives in the
[`tail-acl` README](../../README.md).

## Run it

```sh
tail-acl --file acl/acl.hujson lint
```

The run is pure: no credentials, no network. Every finding carries a stable
id, a severity, a locator such as `grants[2].dst[0]`, evidence, a remediation
hint, and a decision trace.

For a machine consumer, take the JSON envelope:

```sh
tail-acl --format json --file acl/acl.hujson lint
```

## Triage by severity

Severities rank `advice` < `info` < `warn` < `error`. Work them in that order
from the top:

1. **`error`** — the policy is broken in a way that cannot be intended. A
   reference names something undefined, or a destination tag has no
   `tagOwners` entry, so no node can ever carry it. Fix these first.
2. **`warn`** — the policy is probably not what you meant. An over-broad `*`,
   a grant that can never match, or a grant duplicated from an earlier one.
3. **`info`** — a definition nothing references. Usually dead weight left by a
   rename; occasionally deliberate.
4. **`advice`** — a heuristic suggestion, not a defect. It appears in the
   default complete report but sits below the default failure floor, so it does
   not fail the run unless you ask for `-severity advice`. See the authoring
   loop below.

## Choose the threshold

With no `-severity`, `lint` reports everything but fails only on `warn` and
`error`. Supplying the flag sets the lowest severity it both reports and fails
on:

```sh
tail-acl --file acl/acl.hujson lint                   # show all; fail on warn and error
tail-acl --file acl/acl.hujson lint -severity error   # show/fail on only hard breakage
tail-acl --file acl/acl.hujson lint -severity warn    # show/fail on warn and error
tail-acl --file acl/acl.hujson lint -severity advice  # show/fail on everything
```

The value is one floor, not an exact inclusion list: `-severity warn` already
includes `warn` and the more-severe `error`, so `-severity=warn,error` is invalid
and unnecessary. When an explicit floor withholds findings, the versioned JSON
`findings` array and `lint_summary` still cover the whole policy, and the human
trailer names what it withheld —

```text
tail-acl: no findings at or above warn; 2 total: 0 error, 0 warn, 1 info, 1 advice (-severity advice shows/fails on all)
```

That example comes from an explicit `-severity warn`. A policy with nothing to
report reads differently, `no policy hygiene findings in acl/acl.hujson`.

## Keep IdP-synced groups out of the findings

A SCIM/IdP-synced group is named `group:<name>@<domain>` and resolves at the
control plane, so it never appears in the policy's local `groups` map. `lint`
exempts that shape from `undefined-reference` by default and reports the count
instead:

```sh
tail-acl --file acl/acl.hujson lint                              # exempt, counted
tail-acl --file acl/acl.hujson lint -scim-domains corp.example   # only this domain
tail-acl --file acl/acl.hujson lint -strict-scim-groups          # no exemption
```

The exemption is a name-shape heuristic, so it cannot tell you whether a synced
group actually exists or who belongs to it — only `plan` and `validate` consult
the control plane. Both halves must be non-empty, so a templated
`group:${TEAM}@${DOMAIN}` with an unset variable still reports as broken.

## Check Tailscale Services

A Service (`svc:<name>`) resolves at the control plane, so like a synced group
it is never an `undefined-reference` and is counted rather than flagged.
Services are destination-only — a `svc:` on a rule's source side is a
`svc-in-source` warning.

```sh
tail-acl --file acl/acl.hujson lint                     # offline: shape only
tail-acl --file acl/acl.hujson lint -online-validation  # also: does it exist?
```

`-online-validation` needs `--tailnet` plus either `--api-key` or an OAuth
client (`--oauth-client-id` / `--oauth-client-secret`). Without them it logs a
warning to stderr and reports the offline findings alone. With credentials that
are *rejected*, it exits `2` — a check that never ran must not read as a clean
policy — while still printing the offline findings.

A service that does not exist yet is a `warn`, not an `error`, because
Tailscale accepts a policy naming a service you have not created. That matters
for gating: at the default threshold a `warn` fails the run, so a pipeline that
creates the policy before the service should pair `-online-validation` with
`-severity error`.

Tune the wildcard check separately with `-wildcard`:

- `any-to-any` (default) flags only a grant whose `src` and `dst` are both `*`
- `any` flags every `*`
- `off` disables the check

## Close the loop on a broad-rule advisory

`broad-rule-untested` fires when a blanket source reaches a concrete
destination on every port, with no posture or `via` gate and no deny assertion
naming that destination. It is a prompt, not a verdict.

Advisories are visible by default but sit below the default failure floor. To
make them gate the run, lower the floor explicitly:

```sh
tail-acl --file acl/acl.hujson lint -severity advice
```

That exits `1` while any advisory stands — deliberate, since you are asking to
be held to them. Run without the flag for a gate that ignores them.

When the policy supplies a concrete port, the advisory includes a compact JSON
test to paste into `tests`. That gives you a deny-first authoring loop:

1. Paste the suggested assertion into the policy's `tests`.
2. Run `tail-acl --file acl/acl.hujson test`. It goes red, because the broad
   grant does reach that destination.
3. Narrow the grant until the test goes green.
4. The deny assertion now covers the destination, so the advisory goes quiet.

Only `deny` assertions count as coverage, and coverage compares the
destination host selector exactly, ignoring source and port.

If the policy supplies no concrete source or no concrete port, the advisory
stays but the suggestion is omitted rather than invented.

## Exclude a destination everyone is meant to reach

Some broad destinations are correct. Record that decision in a reviewed
config rather than lowering the threshold:

```hujson
{
  "checks": {
    "broad-rule-untested": {
      // Destinations everyone is supposed to reach.
      "allowBroad": ["tag:printer", "tag:logging"],
    },
  },
}
```

```sh
tail-acl --file acl/acl.hujson lint -config acl/lint.hujson
```

Unknown fields fail the run instead of silently discarding an exclusion.
Exclusions are keyed by destination, so they stay stable when merged policy
fragments reorder grants.

## Gate it in CI

```sh
tail-acl --file acl/acl.hujson lint -severity warn
```

Exit `0` means nothing at or above the threshold; exit `1` means there is. The
log shows only findings at or above it too, but the trailer still counts the
rest, so a CI run stays honest about what it chose not to gate on.

Exit `2` is a usage or input error and never a policy verdict — fail the build
loudly on it rather than treating it as "clean". See
[Exit codes](../reference/exit-codes.md) and
[Gate policy changes in CI](../../../docs/how-to/gate-policy-changes-in-ci.md).

## What lint will not tell you

`lint` is deliberately **node-blind**. Whether a tag is carried by a real
device, whether a route is approved, whether a key is about to expire — those
need the live device inventory, and they belong to `tailnet-audit`.

The discriminator is "does this finding need the live fleet?" If yes, it is
not a `lint` finding.

The same blindness applies to IdP-synced groups: an offline `lint` recognizes
the `group:<name>@<domain>` shape but cannot confirm the group exists or that
anyone is in it. A typo'd synced group inside an exempted domain therefore
passes an offline `lint`.

`-online-validation` narrows this rather than closing it: that mode POSTs the
policy to the control plane and turns any "is not syncing from SCIM" warning it
returns into a `scim-group-unsynced` lint finding. Whether a group that does not
exist *at all* produces that particular warning depends on control-plane
wording this repository cannot exercise, so treat `validate` as the check that
settles a typo.

## Related

- [Adopt tail-acl for an existing tailnet](./bootstrap-existing-tailnet.md)
- [Offline evaluation and safety](../explanation/offline-evaluation.md)
