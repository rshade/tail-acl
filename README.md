# tail-acl

Compile, validate, test, check, lint, plan, and upload a Tailscale ACL policy.
`tail-acl` makes typed edits to a policy file, deep-merges commented HuJSON
sources into one strict-JSON policy, runs its native network assertions,
ad-hoc reachability checks, and static hygiene lints locally, and talks to
Tailscale's policy-file API to validate a candidate, diff it against the live
tailnet, or upload it.

> **Module** `github.com/rshade/tailscale-utils/tail-acl`. Conforms to the AX
> conventions in [`../CLAUDE.md`](../CLAUDE.md#ax-conventions-the-shared-standard):
> the command result goes to **stdout** (human text, or a versioned JSON
> envelope with `-format json`); logs and errors go to **stderr**.

It ships three binaries: `tail-acl` (the primary CLI), plus the focused helpers
`hujson-merge` (the merge engine) and `acl-upload` (upload/validate). The
helpers' behaviour is also available as `tail-acl merge` / `tail-acl upload`;
prefer `tail-acl` for the full AX-conformant contract.

## Build

```sh
go build -o tail-acl ./cmd/tail-acl
# stamp a release version:
go build -ldflags "-X main.version=v0.1.0" -o tail-acl ./cmd/tail-acl
```

`make build` at the monorepo root builds all three binaries into `bin/`.

## Usage

```sh
# Typed edits (require a .json target so HuJSON comments are never rewritten):
tail-acl --file acl.json grant add --src autogroup:member --dst tag:web --ip tcp:443
tail-acl --file acl.json grant remove --index 0
tail-acl --file acl.json tag-owner add tag:web autogroup:admin
tail-acl --file acl.json host set web 100.64.0.10
tail-acl --file acl.json posture set posture:labCompliant "custom:labCompliant == true"
tail-acl --file acl.json posture remove posture:labCompliant
tail-acl --file acl.json grant add --src autogroup:member --dst tag:web --ip tcp:443 --src-posture posture:labCompliant

# Compile commented HuJSON sources into one strict-JSON policy:
tail-acl --file acl/acl.generated.json merge --dir initial-30 --dir peer-relay-internal

# Run the policy's top-level tests locally (no credentials or network):
tail-acl --file acl/acl.generated.json test
tail-acl -format json --file acl/acl.generated.json test
tail-acl -strict --file acl/acl.generated.json test  # fail on any unparseable rule

# Ask one reachability question locally (no credentials or network):
tail-acl --file acl/acl.generated.json check --src alice@example.com --dst tag:web:443
tail-acl --file acl/acl.generated.json check --src tag:app --dst tag:db --port 5432
tail-acl -format json --file acl/acl.generated.json check --src group:dev --dst web:443

# Statically lint policy hygiene (no credentials or network):
tail-acl --file acl/acl.generated.json lint
tail-acl --file acl/acl.generated.json lint -severity error   # only fail on errors
tail-acl --file acl/acl.generated.json lint -wildcard any      # flag every standalone *

# Talk to the tailnet (needs TAILSCALE_API_KEY + TAILSCALE_TAILNET):
tail-acl --file acl/acl.generated.json validate   # server-side validation
tail-acl --file acl/acl.generated.json plan       # read-only diff vs the live policy
tail-acl --file acl/acl.generated.json upload      # apply the policy

# Machine surfaces:
tail-acl -schema                                   # machine-readable command/flag catalog
tail-acl --version                                 # version + VCS revision
tail-acl -format json --file acl.json grant add …  # JSON result envelope on stdout
```

### Commands

| Command | Purpose |
| --- | --- |
| `grant add` | Append a grant (`--src`, `--dst`, `--ip`; `--src-posture` optional; repeatable, order-insensitive, idempotent) |
| `grant remove` | Remove a grant by zero-based `--index` |
| `tag-owner add` | Add an owner to a tag |
| `host set` | Set a host alias to an address |
| `posture set` | Add or replace a posture's expression list |
| `posture remove` | Remove a posture definition |
| `merge` | Deep-merge every ACL `.json`/`.hujson` file across `--dir`s into the `--file` output |
| `validate` | Validate the policy (and its policy tests) via the Tailscale API |
| `test` | Evaluate every top-level `tests` `accept`/`deny` assertion locally (`-strict` to reject unparseable rules) |
| `check` | Answer whether one `--src` can reach `--dst DST:PORT` locally (`--port PORT` is also accepted) |
| `lint` | Statically report policy-hygiene findings — dead grants, undefined refs, over-broad `*` (`-severity`, `-wildcard`) |
| `plan` | Fetch the deployed policy and print a validated unified diff, without applying |
| `upload` | Upload the policy to the tailnet (`--if-match` for optimistic concurrency) |

### Global flags

`--file` (policy path), `--tailnet` / `--api-key` (default to `TAILSCALE_TAILNET` /
`TAILSCALE_API_KEY`), `--if-match` (ETag for `upload`), `-strict` (make local
`test`/`check` evaluation reject any unparseable rule), `-format human|json`,
`-verbose`, `--version`, `-schema`. `TAILSCALE_API_URL` overrides the API base URL
(used by tests).

### Exit codes

- `0` success; all policy assertions passed; `check` reports reachable; `lint` found nothing at or above the threshold
- `1` operation or policy assertion failed; `check` reports not reachable; `lint` found issues at or above the threshold
- `2` usage, input, or collection error (including a local policy decision that cannot be evaluated)

## Design

Typed edits go through Tailscale's public `tailscale.ACL` schema with
unknown-field rejection and atomic writes, so an edit can never silently drop
policy data the client does not model, and typed edits refuse a non-`.json`
target so HuJSON comments and formatting survive. `merge` has two paths:
`MergePair` preserves comments (single base + snippet), while `MergeDirectories`
calls `Standardize()` and strips comments, which is why compiled output is
comment-free strict JSON. `plan` validates the candidate server-side before
diffing, so a broken policy fails the plan rather than the upload.

### Posture authoring: deliberate prefix asymmetry

`posture set` and `posture remove` accept a posture name in two forms: an
explicit `posture:NAME` or a bare `NAME`, both of which resolve to the canonical
`posture:NAME` in the policy. A different selector prefix (`tag:`, `group:`,
etc.) or an empty name is a usage error (exit 2). By contrast, `grant add
--src-posture` requires the explicit `posture:` prefix and does not auto-complete
a bare name — a bare `labCompliant` is rejected (exit 2), not silently treated as
`posture:labCompliant`.

This asymmetry is deliberate: `posture set`/`remove` are *declarations* where the
subcommand itself establishes the postures namespace, so a bare name is
unambiguous; `--src-posture` is a *reference* sitting alongside other
fully-qualified selector flags (`--src`, `--dst`), where the prefix carries
meaning and silently inventing one would hide a typo. Authoring does not validate
that a referenced posture is actually defined — that dangling-reference check is
`tail-acl lint`'s job (issue #17), not authoring's.

`test` is a pure evaluator over the candidate file's network-level grants and
legacy ACLs. Each `accept` or `deny` destination becomes one stable assertion
result with pass/fail status, evidence, and a decision trace. The evaluator
supports groups, hosts, IP sets, literal IPs/CIDRs, tags and other exact
selectors, `autogroup:member`, `autogroup:self`, `autogroup:internet`, and
single/list/range port expressions. Application-only capabilities do not grant
network access. Because posture and `via` routing depend on semantics that
cannot be reproduced safely from the policy alone, a matching rule that uses
either returns exit `2` instead of guessing; use `validate` for the authoritative
control-plane evaluation in that case.

Rule *syntax* is scanned once up front, before any assertion runs, so the
result never depends on which assertion happened to reach which rule. An
element the evaluator cannot parse — most often an ACL destination written
without its port, as in `"dst": ["tag:web"]` — can never match, so a verdict
reached alongside one may be wrong. By default such a rule is logged at `warn`
on stderr and listed in the envelope's `skipped` array while the remaining
assertions are still reported; `-strict` refuses to report verdicts computed
around it at all and exits `2`. Prefer `-strict` in CI, where a silently
mis-evaluated `deny` assertion is the failure you least want to pass.

### `check` design decision: local evaluation

`check` deliberately uses the same pure evaluator as `test`; it does not call
the control-plane ACL preview endpoint. A local result is deterministic for an
unchanged compiled policy, works before credentials or a tailnet are available,
and is golden-fixture testable. It also makes the command useful in an agent's
edit → check → plan workflow without leaking a read-only operation onto the
network. The JSON envelope adds `allowed`, `source`, `destination`, `port`,
`evidence`, `trace`, and the matching `grant_index` or `acl_index`; these are
additive schema-version-1 fields.

The evaluator treats a port-only question like a native Tailscale policy test
with no `proto`: either TCP or UDP access is sufficient. It understands network
grants and legacy ACLs, groups, hosts, IP sets, exact tag/user selectors,
supported autogroups, IP/CIDR containment, bare or protocol-qualified ports,
lists, and ranges. Application capabilities alone do not grant network access.
As Tailscale does, a policy with neither a `grants` nor an `acls` section uses
the implicit default-allow policy; an explicitly empty section denies access.

This local choice has an explicit safety boundary. Device posture and `via`
routing depend on facts outside the policy snapshot, so a matching rule using
either returns exit `2` rather than guessing. Use Tailscale's credentialed
[ACL preview API](https://tailscale.com/docs/reference/trust-credentials) or
server-side `validate` when those live control-plane semantics are required;
`check` never silently falls back to the network.

### `lint`: static policy hygiene

`valid` is not `healthy`: a policy can pass validation while carrying grants
that match nothing, destination tags no one owns, references to tags/groups
that were renamed away, or an over-broad `*` that grants more than intended.
`lint` is a pure pass over the loaded policy — no credentials, no network — that
reports these as findings, each with a stable id, severity, a locator (e.g.
`grants[2].dst[0]`), evidence, a remediation hint, and a decision trace.

| Finding | Severity | Fires when |
| --- | --- | --- |
| `undefined-reference` | error | a `src`/`dst` names a `group:`/`tag:`/`ipset:`/host alias that is not defined |
| `dst-tag-no-owner` | error | a destination `tag:` has no `tagOwners` entry, so no node can carry it |
| `overbroad-wildcard` | warn | an over-broad `*` (see `-wildcard`) |
| `grant-empty` | warn | a grant has an empty required selector list and can never match |
| `duplicate-grant` | warn | a grant is identical to an earlier one (order-insensitive) |
| `unused-tag`/`-group`/`-host`/`-ipset` | info | a definition is referenced by no rule |

`-severity info|warn|error` (default `warn`) sets the lowest severity that makes
the run exit `1`; below it the finding is still reported but the run exits `0`.
`-wildcard any-to-any|any|off` (default `any-to-any`) tunes the wildcard check:
`any-to-any` flags only a grant whose `src` and `dst` are both `*` (a standalone
`*` is common and allowed), `any` flags every `*`, and `off` disables it.
Autogroups are treated as defined by their `autogroup:` prefix alone, so a new
autogroup Tailscale ships never false-positives as an undefined reference.

Lint is deliberately **node-blind**: whether a tag is carried by a real device
is a control-plane coverage question that belongs to `tailnet-audit`, not here.
The discriminator is "does the finding need the live device inventory?" — if
yes, it is not a `lint` finding.

## License

[Apache-2.0](LICENSE).
