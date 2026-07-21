# tail-acl

Compile, validate, plan, and upload a Tailscale ACL policy. `tail-acl` makes
typed edits to a policy file, deep-merges commented HuJSON sources into one
strict-JSON policy, and talks to Tailscale's policy-file API to validate a
candidate, diff it against the live tailnet, or upload it.

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

# Compile commented HuJSON sources into one strict-JSON policy:
tail-acl --file acl/acl.generated.json merge --dir initial-30 --dir peer-relay-internal

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
| `grant add` | Append a grant (`--src`, `--dst`, `--ip`; repeatable, order-insensitive, idempotent) |
| `grant remove` | Remove a grant by zero-based `--index` |
| `tag-owner add` | Add an owner to a tag |
| `host set` | Set a host alias to an address |
| `merge` | Deep-merge every ACL `.json`/`.hujson` file across `--dir`s into the `--file` output |
| `validate` | Validate the policy (and its policy tests) via the Tailscale API |
| `plan` | Fetch the deployed policy and print a validated unified diff, without applying |
| `upload` | Upload the policy to the tailnet (`--if-match` for optimistic concurrency) |

### Global flags

`--file` (policy path), `--tailnet` / `--api-key` (default to `TAILSCALE_TAILNET` /
`TAILSCALE_API_KEY`), `--if-match` (ETag for `upload`), `-format human|json`,
`-verbose`, `--version`, `-schema`. `TAILSCALE_API_URL` overrides the API base
URL (used by tests).

### Exit codes

- `0` success
- `1` operation failed (API rejected the policy, network error, unreadable file)
- `2` usage or input error (bad flags, missing command, missing credentials)

## Design

Typed edits go through Tailscale's public `tailscale.ACL` schema with
unknown-field rejection and atomic writes, so an edit can never silently drop
policy data the client does not model, and typed edits refuse a non-`.json`
target so HuJSON comments and formatting survive. `merge` has two paths:
`MergePair` preserves comments (single base + snippet), while `MergeDirectories`
calls `Standardize()` and strips comments, which is why compiled output is
comment-free strict JSON. `plan` validates the candidate server-side before
diffing, so a broken policy fails the plan rather than the upload.

## License

[Apache-2.0](LICENSE).
