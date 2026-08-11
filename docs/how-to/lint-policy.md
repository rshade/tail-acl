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
4. **`advice`** — a heuristic suggestion, not a defect. Below the default
   threshold, so `lint` withholds it until you ask with `-severity advice`. See
   the authoring loop below.

## Choose the threshold

`-severity` sets the lowest severity `lint` reports and fails on:

```sh
tail-acl --file acl/acl.hujson lint -severity error   # only hard breakage
tail-acl --file acl/acl.hujson lint                   # default: warn and above
tail-acl --file acl/acl.hujson lint -severity advice  # everything, advisories fail too
```

A finding below the threshold is neither printed nor carried in the JSON
`findings` array. The counts survive it, though: `lint_summary` covers the whole
policy at every threshold, and the trailer names what it withheld —

```text
tail-acl: no findings at or above warn; 2 total: 0 error, 0 warn, 1 info, 1 advice (-severity advice shows all)
```

A policy with nothing to report reads differently, `no policy hygiene findings
in acl/acl.hujson`, so a quiet run never leaves you guessing whether the policy
was clean or the threshold was high.

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

Tune the wildcard check separately with `-wildcard`:

- `any-to-any` (default) flags only a grant whose `src` and `dst` are both `*`
- `any` flags every `*`
- `off` disables the check

## Close the loop on a broad-rule advisory

`broad-rule-untested` fires when a blanket source reaches a concrete
destination on every port, with no posture or `via` gate and no deny assertion
naming that destination. It is a prompt, not a verdict.

Advisories sit below the default threshold, so start by asking for them:

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

The same blindness applies to IdP-synced groups: `lint` recognizes the
`group:<name>@<domain>` shape but cannot confirm the group exists or that anyone
is in it. A typo'd synced group inside an exempted domain therefore passes
`lint` and is caught only by `validate`.

## Related

- [Adopt tail-acl for an existing tailnet](./bootstrap-existing-tailnet.md)
- [Offline evaluation and safety](../explanation/offline-evaluation.md)
