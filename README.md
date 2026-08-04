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
# Typed edits (comments and key order survive in .json and .hujson):
tail-acl --file acl.json grant add --src autogroup:member --dst tag:web --ip tcp:443
tail-acl --file acl.json grant remove --index 0
tail-acl --file acl.hujson tag-owner add tag:web autogroup:admin  # comments preserved
tail-acl --file acl.json host set web 100.64.0.10
tail-acl --file acl.json posture set posture:labCompliant "custom:labCompliant == true"
tail-acl --file acl.json posture remove posture:labCompliant

# An expression beginning with a dash needs a `--` terminator, and `--comment`
# must precede it:
tail-acl --file acl.json posture set posture:lab --comment "note" -- "-1 < custom:score"

# Author a comment on the entry the command creates:
tail-acl --file acl.json grant add --src tag:app --dst tag:db --ip tcp:5432 \
  --comment "Database access for application nodes"
tail-acl --file acl.hujson host set web 100.64.0.10 --comment "Legacy monitoring endpoint"
tail-acl --file acl.json host set web 100.64.0.10 --comment "Now the canary" --overwrite-comment
tail-acl --file acl.json grant add --src autogroup:member --dst tag:web --ip tcp:443 --src-posture posture:labCompliant

# Compile commented HuJSON sources into one strict-JSON policy:
tail-acl --file acl/acl.generated.json merge --dir initial-30 --dir peer-relay-internal

# Run the policy's top-level tests locally (no credentials or network):
tail-acl --file acl/acl.generated.json test
tail-acl -format json --file acl/acl.generated.json test
tail-acl -strict --file acl/acl.generated.json test  # fail on any unparseable rule
tail-acl --indeterminate=fail --file acl/acl.generated.json test  # fail CI if proof is incomplete
tail-acl --file acl/acl.generated.json test --watch  # re-run on every save, Ctrl-C to stop
tail-acl -format json --file acl/acl.generated.json test --watch  # NDJSON, one verdict per line

# Ask one reachability question locally (no credentials or network):
tail-acl --file acl/acl.generated.json check --src alice@example.com --dst tag:web:443
tail-acl --file acl/acl.generated.json check --src tag:app --dst tag:db --port 5432
tail-acl -format json --file acl/acl.generated.json check --src group:dev --dst web:443
tail-acl --file acl/acl.generated.json check --src tag:app --dst tag:dns:53 --proto udp

# Statically lint policy hygiene (no credentials or network):
tail-acl --file acl/acl.generated.json lint
tail-acl --file acl/acl.generated.json lint -severity error   # only fail on errors
tail-acl --file acl/acl.generated.json lint -wildcard any      # flag every standalone *

# Talk to the tailnet (needs TAILSCALE_API_KEY + TAILSCALE_TAILNET):
tail-acl --file acl/acl.generated.json pull       # bootstrap from the deployed policy
tail-acl --file acl/acl.generated.json validate   # server-side validation
tail-acl --file acl/acl.generated.json plan       # read-only diff vs the live policy
tail-acl --file acl/acl.generated.json upload      # apply the policy

# Machine surfaces:
tail-acl -schema                                   # machine-readable command/flag catalog
tail-acl --version                                 # version + VCS revision
tail-acl -format json --file acl.json grant add …  # JSON result envelope on stdout
```

### Bootstrap an existing tailnet

When adopting `tail-acl` for a tailnet whose policy was authored in the admin
console, pull the deployed policy before making local edits:

```bash
tail-acl --file acl/acl.hujson pull
```

`pull` writes the deployed bytes verbatim, including comments and key order, and
reports the matching ETag. It is an adoption step, not a routine synchronization
workflow: it refuses to replace an existing `--file` unless `--force` is supplied.
After editing, run `plan`, then pass the reported ETag to `upload --if-match`.

**Warning:** `upload` replaces the entire deployed policy with `--file`; it does
not merge a fragment into the live policy. Always plan a complete policy first.

### Commands

| Command | Purpose |
| --- | --- |
| `grant add` | Append a grant (`--src`, `--dst`, `--ip`; `--src-posture` optional; repeatable, order-insensitive, idempotent; `--comment`) |
| `grant remove` | Remove a grant by zero-based `--index` |
| `tag-owner add` | Add an owner to a tag (`--comment`) |
| `host set` | Set a host alias to an address (`--comment`) |
| `posture set` | Add or replace a posture's expression list (`--comment`) |
| `posture remove` | Remove a posture definition |
| `merge` | Deep-merge every ACL `.json`/`.hujson` file across `--dir`s into the `--file` output |
| `validate` | Validate the policy (and its policy tests) via the Tailscale API |
| `test` | Evaluate every top-level network `tests` `accept`/`deny` assertion locally; `sshTests` is preserved but not evaluated (`-strict` rejects unparseable network rules; `--indeterminate` controls the exit policy for unsettleable assertions; `--watch` re-runs on every change and never exits non-zero for a verdict) |
| `check` | Answer whether one `--src` can reach `--dst DST:PORT` locally (`--port PORT` and `--proto tcp\|udp\|sctp\|any` are also accepted) |
| `lint` | Statically report policy-hygiene findings — dead grants, undefined refs, over-broad `*` (`-severity`, `-wildcard`) |
| `pull` | Bootstrap `--file` from the deployed policy (`--force` permits an intentional overwrite) |
| `plan` | Fetch the deployed policy and print a validated unified diff, without applying |
| `upload` | Replace the entire deployed policy with `--file` (`--if-match` for optimistic concurrency) |

### Global flags

`--file` (policy path), `--tailnet` / `--api-key` (default to `TAILSCALE_TAILNET` /
`TAILSCALE_API_KEY`), `--if-match` (ETag for `upload`), `-strict` (make local
`test`/`check` evaluation reject any unparseable rule),
`--indeterminate fail|warn|ignore` (test exit policy, default `warn`),
`-format human|json`, `-verbose`, `--version`, `-schema`.
`TAILSCALE_API_URL` overrides the API base URL (used by tests).

### Exit codes

- `0` success, including server validation that returned warnings with no errors
  and no message; all policy assertions passed, or `test` used
  `--indeterminate=ignore`, which suppresses the exit code but not the finding —
  the envelope still reports `status: "indeterminate"` and a non-zero
  `test_summary.indeterminate`; `check` reports reachable; `lint` found nothing
  at or above the threshold
- `1` operation or policy assertion failed (including indeterminate under
  `--indeterminate=fail`); `check` reports not reachable; `lint` found issues at
  or above the threshold
- `2` usage, input, or collection error. For `pull`, `validate`, and `plan` this also
  covers a control plane that never judged the policy — expired credentials,
  rate limiting, a server fault, an unreadable response body, a redirect that
  dropped the request, or an unreachable API. No verdict is printed on stdout
  for a request that reached no answer
- `10` `check` is indeterminate, `test` under the default `--indeterminate=warn`
  had an assertion it could not settle, or `validate` and `plan` got a response
  they cannot read as a verdict — warnings with no errors alongside a message,
  or a detail entry carrying neither errors nor warnings. A rule or a response
  might have been clean, but nothing available could prove it was. This is
  deliberately not a denial: see
  [the safety boundary](#the-safety-boundary) below.

## Design

Typed edits go through a local `Policy` type that embeds Tailscale's public
`tailscale.ACL` schema and extends the pinned client where it lags the documented
policy-file schema (currently `sshTests` and `ssh[].acceptEnv`). Decoding still
rejects every unmodelled field, and writes are atomic, so an edit can never
silently drop policy data. Duplicate object members are rejected too: Go's JSON
decoder resolves them last-wins while HuJSON resolves them first-wins, so a
policy carrying both would be validated through one member and patched through
the other.

Typed edits apply an RFC 6902 patch to either `.json` or `.hujson` input.
**Comments, key order, and the key's own spelling survive** — a policy authored
in the legacy capitalized style (`"TagOwners"`) keeps that spelling. Removing
the last entry from a block empties it rather than deleting the key, so a
comment attached to that block is not carried out with it.

The four authoring commands can also **write** a comment. `--comment TEXT`
attaches `// TEXT` to the exact node the command authored: the new `grants`
element for `grant add`, the added owner element for `tag-owner add`, and the
`hosts` or `postures` member for `host set` and `posture set`. `TEXT` is one
non-empty line — a carriage return or newline is rejected with exit `2` and the
file is left byte-identical — and the `//` marker is supplied by the CLI.

By default a comment is **appended** to whatever the entry already carries, and
an exact duplicate is suppressed, so re-running a command never stacks the same
line twice. Pass `--overwrite-comment` to replace the entry's own comments
instead; a comment on the line the *preceding* entry ends on belongs to that
entry and is left alone either way. `--overwrite-comment` without `--comment` is
a usage error.

Because a comment is part of the entry, it participates in the idempotence
check: re-running a command with the same value and the same comment reports
`no_changes` and leaves the file untouched, while adding a missing comment to an
entry that already has the right value is a real change and reports `ok`. This
is why `host set` and `posture set` now report `no_changes` on a repeat, which
they did not before.

One consequence is worth stating plainly: **authoring a comment into a `.json`
file makes it stop being strict JSON.** JSON has no comments, so the file
becomes HuJSON and the formatter also adds trailing commas throughout. Nothing
in this repo is affected — `validate`, `plan`, and `upload` post the raw bytes
and Tailscale's API accepts HuJSON — but an external consumer that runs `jq` (or
any strict JSON parser) over the policy will break. Rename the file to
`.hujson`, or leave the comment off that policy.

Layout, however, is **not** preserved: the file is rewritten in HuJSON's
canonical format. Indentation is normalized to tabs, column alignment is
re-derived for the whole document, line endings become LF, and a file that is
already non-standard JSON gains trailing commas throughout. A policy that is
strict JSON stays strict JSON — unless `--comment` authors one into it, which is
the single exception — so `jq` and API consumers are otherwise unaffected. The
practical consequence is that the first typed edit against a policy not already
in canonical form produces a diff touching every line; running one edit on its
own first keeps that reformat out of the review for the real change. Authoring a
comment onto a compact array or object expands it, because HuJSON always expands
a composite whose leading extra contains a newline.

`merge` has two paths:
`MergePair` preserves comments (single base + snippet), while `MergeDirectories`
calls `Standardize()` and strips comments, which is why compiled output is
comment-free strict JSON. `plan` validates the candidate server-side before
diffing, so a broken policy fails the plan rather than the upload.

Server validation warnings are non-fatal. A response in which every detail has
one or more `warnings`, no `errors`, and no `message` exits `0`; each warning is
logged on stderr, and `-format json` preserves it under `validation.warnings`.
Validation failures exit `1` and retain per-user detail under
`validation.failures`. `validate` and `plan` both emit the additive `validation`
object, whose two arrays are present even when empty. Classification is
structural: the CLI reads which fields are present, never the prose inside the
server's `message`, so no verdict depends on wording the control plane is free
to change.

Three responses deliberately do not produce a pass or a fail:

- **Warnings alongside a message exit `10`, indeterminate.** The captured
  evidence shows `message` is a failure channel in its own right — the parse
  error in `internal/tailapi/testdata/validate_d_parse_error.json` carries a
  message and no `data` at all — but the warnings channel itself was never
  observed, because the SCIM probe was unavailable when those fixtures were
  taken. Calling that combination valid would risk a green run on a rejection
  whose reason lived only in the message; calling it invalid would fail every
  warning-bearing policy if the server simply narrates warnings there. Until a
  capture settles it, `tail-acl` reports that it cannot tell.
- **A detail carrying neither `errors` nor `warnings` exits `10`.** The pinned
  client already dropped one documented per-detail field, which is the whole
  reason this command owns its request — so an entry this client cannot read is
  evidence the response shape moved, not evidence the policy is bad. Filing it
  under `validation.failures` would name an identity in the envelope with no
  error text behind the accusation, so those entries appear in neither array and
  the stderr diagnostic names what could not be read.
- **A control plane that never judged the policy exits `2`.** Expired
  credentials, rate limiting, the `5xx` family, a body that does not decode, a
  redirect that rewrote the `POST` into a `GET` (which discards the policy), and
  an unreachable API all mean the policy was never read, so stdout carries no
  envelope at all rather than a verdict on a file the server never saw. A
  judgement requires HTTP `200`, or a `400` that carries per-user `data` to back
  it — a bare `400` is the generic "your request was wrong" and is treated as a
  request this endpoint never answered.

This command calls `/acl/validate` directly using the initialized v2 client's
URL, HTTP transport, User-Agent, and authentication configuration. The pinned
client's `PolicyFile().Validate` cannot express valid-with-warnings and discards
the documented warning field and typed detail on HTTP 200. The owned request is
therefore deliberately limited to this endpoint; upload and every other API
operation continue to use the official client resource methods.

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
legacy ACLs. Each top-level `tests` `accept` or `deny` destination becomes one
stable assertion result with pass/fail/indeterminate status, evidence, and a
decision trace. A deny passes only after every rule has been proved
inapplicable. If a rule's source and destination overlap the assertion but its
port or protocol cannot be understood, the denial is `indeterminate`, never a
pass.
Top-level `sshTests` assertions are loaded and preserved across typed edits but
are not evaluated: SSH assertions use SSH usernames and three verdicts
(`accept`, `check`, and `deny`), so they require a separate evaluator. A run
never stays quiet about that gap — it warns on stderr and reports the count as
`ssh_tests_skipped` in the JSON envelope, so a passing run can never be read as
having checked assertions it skipped. The
network evaluator supports groups, hosts, IP sets, literal IPs/CIDRs, tags and
other exact selectors, `autogroup:member`, `autogroup:self`, `autogroup:internet`, and
single/list/range port expressions. Application-only capabilities do not grant
network access. Because posture and `via` routing depend on semantics that
cannot be reproduced safely from the policy alone, a matching rule that uses
either makes the assertion indeterminate instead of guessing; use `validate`
for the authoritative control-plane evaluation in that case.

Rule *syntax* is scanned once up front, before any assertion runs, so the
result never depends on which assertion happened to reach which rule. An
element the evaluator cannot parse — most often an ACL destination written
without its port, as in `"dst": ["tag:web"]` — might have matched if it were
understood. It is logged at `warn` on stderr and listed in the envelope's
policy-scoped `skipped` array. Separately, only assertions whose narrowed
evaluation path reaches that element are `indeterminate`; unrelated denials
remain proven passes. `-strict` is the opt-in policy-rejection posture: it
refuses to report any verdicts when `skipped` is non-empty and exits `2`.

`--indeterminate=fail|warn|ignore` controls `test`'s exit code when there are
no definite failures. `warn` is the default and exits `10`; `fail` exits `1`
for CI gates; `ignore` exits `0` for migrations. Every mode keeps the assertion
status, count, `skipped` entries, and stderr warnings intact. The flag is
test-only: `check`'s three-state verdict is its product and always exits `10`
when it cannot settle the query.

Local evaluation assumes the policy's references are valid. An undefined
`group:`, host alias, or `ipset:` reference matches nothing locally even though
the control plane rejects that policy. `tail-acl lint` catches those dangling
references; it does **not** catch an unreadable port or protocol, so it will not
predict an exit `10`. Server-side `validate` is the only check that catches
both. `-strict` checks unreadable network-rule syntax, not dangling references.

Trace entries are human-readable evidence, not a stable contract — their wording
changes as the evaluator learns to name a cause more precisely. Machine
consumers should branch on `status` (or `access` for `check`) and read
`evidence`, never grep the `trace` array.

### Compatibility

Two changes affect callers that branch on exit codes, in the same spirit as the
`grant_index` note above:

- `test` previously exited `0` when an unparseable rule lay on an assertion's
  evaluation path, because such a rule was treated as unable to match — a
  confident wrong pass on a `deny`. It now exits `10` by default. A CI job that
  green-lights on `[ $? -eq 0 ]` will start failing on a policy the tool used to
  bless. Set `--indeterminate=ignore` to restore the old exit code for one
  release while the policy is fixed; the finding stays in the envelope either
  way.
- `check` in the same situation previously reported `access: "deny"` with exit
  `1`; it now reports `access: "indeterminate"` with exit `10`, and omits the
  legacy `allowed` field rather than serializing `false`. There is deliberately
  no opt-out: `check`'s three-state verdict is its product, and a shell caller
  branching on `-eq 1` should treat `10` as "could not prove", not as reachable.
- SCTP joining TCP and UDP as port-carrying widens the protocol-agnostic
  default, so a rule reachable only over SCTP changes verdict without any flag
  being passed. A capability such as `sctp:5432` previously answered no port
  question: `check` reported not reachable, an `accept` assertion over it failed,
  and a `deny` assertion passed. All three now flip. Conversely, the proto-0
  spellings (`*`, `*:443`, `0:443`, a bare `443`) compile to TCP, UDP, and
  ICMP(4+6) and so do **not** grant SCTP — `--proto sctp` needs an explicit
  `sctp:` or `132:` capability.

### `check` design decision: local evaluation

`check` deliberately uses the same pure evaluator as `test`; it does not call
the control-plane ACL preview endpoint. A local result is deterministic for an
unchanged compiled policy, works before credentials or a tailnet are available,
and is golden-fixture testable. It also makes the command useful in an agent's
edit → check → plan workflow without leaking a read-only operation onto the
network. The JSON envelope adds `access`, `allowed`, `source`, `destination`,
`port`, `protocol`, `evidence`, `trace`, and the matching `grant_index` or
`acl_index`; these are additive schema-version-1 fields.

`access` is the three-state verdict (`allow`, `deny`, `indeterminate`) and is
the field to read. `allowed` is the older two-state boolean, kept for existing
consumers and **emitted only for a definite answer** — an indeterminate result
omits it rather than serializing `false`, which would read as a denial.

**One field changed meaning.** `grant_index` / `acl_index` previously named the
rule that *allowed* a query, because they were only ever populated for a match.
They now name the rule that **decided** the answer, which for an indeterminate
result is the rule whose unevaluatable condition blocked a verdict. A consumer
that reads the index without also switching on `access` (or `status`) would
misread a blocking rule as an allowing one. This is additive in shape but not in
meaning, so switch on `access` first.

By default the evaluator treats a port-only question like a native Tailscale
policy test with no `proto`: access under any port-carrying protocol is
sufficient. Those are TCP, UDP, and SCTP — the three Tailscale's packet filter
matches by port; every other protocol needs the entire port range and so answers
no port question. Pass `--proto tcp`, `--proto udp`, or `--proto sctp` to narrow
the question when the distinction matters (`udp:53` versus `tcp:53`). Adding SCTP
to that set widens the default question, so see [Compatibility](#compatibility)
for the verdicts it moves. It understands network
grants and legacy ACLs, groups, hosts, IP sets, exact tag/user selectors,
supported autogroups, IP/CIDR containment, bare or protocol-qualified ports,
lists, and ranges. Application capabilities alone do not grant network access.
As Tailscale does, a policy with neither a `grants` nor an `acls` section uses
the implicit default-allow policy; an explicitly empty section denies access.

### The safety boundary

A policy file does not contain every fact a verdict can depend on. Device
posture, `via` routing, and the role autogroups (`autogroup:admin`,
`autogroup:owner`, the `*-admin` family, `autogroup:auditor`,
`autogroup:shared`) all resolve against control-plane state this evaluator
never sees — as does any autogroup Tailscale adds after this release.

A rule the evaluator cannot *read* lands on the same boundary. A destination
written without its port (`"dst": ["tag:web"]`), an unknown protocol token, or a
malformed port expression might have matched had it been understood, so a query
whose evaluation path reaches one is `indeterminate` rather than a denial.
Unrelated queries — those a readable field already ruled out — stay proven.

Which autogroups can be settled locally depends on the **query as well as the
selector**. `autogroup:tagged` is decidable against `tag:batch` (yes) and
against a user identity (no), but against a bare `100.64.0.9` it needs the
device-to-tag map, so that query is indeterminate. Conversely a role autogroup
is refutable with certainty against a `tag:` source, because a tagged device has
no user owner — reporting `indeterminate` for a settleable question would train
callers to ignore exit `10`.

When a rule clears every condition the evaluator *can* decide and is stopped
only by one it cannot, `check` reports `indeterminate` and exits `10`, naming
the rule and the condition. It does **not** report a denial. `test` reports the
same situation as an `indeterminate` assertion and keeps the rest of the report,
rather than discarding every assertion it had already computed. Collapsing "cannot
tell" into "no" would emit a confident wrong answer, which is the one outcome a
reachability tool must never produce.

The narrowing matters: a rule that fails on destination or port could never
have applied, so it stays a clean `deny` even when its source names an
unresolvable autogroup. Only a rule that would otherwise have matched clouds
the verdict.

Use Tailscale's credentialed
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

### `test --watch`: the save-and-look loop

`--watch` re-runs the assertion suite whenever the policy file's contents change, so authoring is a glance at
a second terminal rather than a command you keep retyping.

```bash
tail-acl --file acl.hujson test --watch              # human output, blank line between runs
tail-acl -format json --file acl.hujson test --watch # NDJSON, one envelope per line
```

Four decisions are worth knowing:

- **It polls, and that is deliberate.** Typed edits and every competent editor replace the file with a
  temp-file-plus-rename, and a filesystem watch registered on a *file* does not survive a rename. Polling
  re-resolves the path every tick and adds no dependency. `--interval` defaults to `500ms`.
- **A change is a content hash, not an mtime.** Rewriting the file with identical bytes re-runs nothing, and a
  run happens only once the digest is identical on two consecutive polls — a quiet period and a guard against
  grading a half-written file, from one mechanism.
- **Under `-format json` the stream is NDJSON**, and every record carries `policy_digest`, the SHA-256 of the
  exact bytes that were graded. Correlate by digest, not by time: it is reproducible, and line order already
  supplies sequence. Single-shot `-format json` is unchanged — still one indented object, still no
  `policy_digest`.
- **It never exits non-zero for a verdict.** An exit code is a point-in-time verdict and a watch loop has no
  single point in time; exit 1 would mean both "your suite is red" and "you interrupted while it happened to
  be red". Interrupt always exits 0, whatever the last run said — use plain `test` in CI. Exit 2 still
  signals the watcher's *own* failures: an unreadable `--file`, a non-positive `--interval`, a flag
  combination that cannot apply, or a write that fails and returns an error, such as a full disk. A save
  that cannot be parsed is none of those — it prints nothing on stdout, logs once to stderr, and leaves the
  loop running. Piping into a reader that exits early, e.g. `tail-acl test --watch | head -1`, does **not**
  return you to a prompt: a broken pipe is only detected by writing, and a watcher that has already graded
  the current file writes nothing until that file changes, so it keeps polling. The *next* save is what
  fails to write, and the outcome there is platform-specific — on Unix the Go runtime raises `SIGPIPE` on
  the failed write to fd 1, and the default disposition kills the process with exit 141 before `--watch`'s
  own error handling ever runs; on Windows, where there is no SIGPIPE, the same failed write is reported as
  an ordinary error, so `--watch` exits 2 through the same path as a full disk. Both are ordinary behavior
  for a streaming tool, not a bug — but stop a watcher by interrupting it, not by closing its reader.

## License

[Apache-2.0](LICENSE).
