# Watch policy tests while editing

Watch mode re-runs the assertion suite every time the policy file changes, so
authoring becomes a glance at a second terminal instead of a command you keep
retyping.

Two modes are available: a local loop that needs no credentials, and an
authoritative loop that also submits each snapshot to Tailscale for
server-side validation.

## Local save-and-check loop

```sh
tsacl --file acl.hujson test --watch
```

The first result prints immediately. After that, the suite re-runs when the
file's contents change and stay stable across two consecutive polls.

Set a different poll interval when the default `500ms` is wrong for your
editor or filesystem:

```sh
tsacl --file acl.hujson test --watch --interval 1s
```

The interval must be a positive duration. A non-positive value exits `2`.

## Machine-readable stream

```sh
tsacl --format json --file acl.hujson test --watch
```

Under `--format json` the stream is NDJSON: one result envelope per line.
Every record carries `policy_digest`, the SHA-256 of the exact bytes that were
graded.

**Correlate by digest, not by timestamp.** The digest is reproducible and line
order already supplies sequence. Single-shot `--format json` is unchanged — one
indented object, and no `policy_digest`.

## Authoritative loop with server validation

`--validate` adds credentialed, read-only calls to Tailscale's `/acl/validate`
endpoint. It is legal only together with `--watch`:

```sh
export TAILSCALE_TAILNET=example.com
export TAILSCALE_API_KEY=tskey-api-...

tsacl --file acl.hujson test --watch --validate
```

Each stable snapshot is evaluated locally *and* submitted unchanged to the
server, then emitted as one digest-correlated block (human) or record
(NDJSON), so the local verdict and the server's answer arrive together.

Four properties matter in practice:

- **Credentials are never implicit.** `--tailnet` plus either `--api-key` or
  an OAuth client (`--oauth-client-id` / `--oauth-client-secret`, or their
  environment equivalents) are required. Credentials sitting in the
  environment never change the behavior of plain `test --watch`; you opt in by
  passing the flag.
- **At most one request is in flight.** One newest snapshot may be pending.
  Newer stable bytes supersede and cancel older work, so a burst of saves does
  not queue up a backlog of stale validations.
- **API unavailability exits `2`** with sanitized evidence. That is a
  collection failure, not a policy verdict — policy verdicts remain stream
  data.
- **An interrupt still exits `0`**, with no record emitted for the cancelled
  request. A Ctrl-C during validation is never reported as an unavailable
  control plane.

## Stopping the watcher

Interrupt it directly, with Ctrl-C.

Do **not** stop it by closing its reader — piping into something that exits
after one record, such as `tsacl test --watch | head -1`, does not return
you to a prompt. See
[Why watch mode behaves the way it does](../explanation/watch-mode.md) for the
mechanism and the platform-specific exit codes.

## Do not use watch mode as a CI gate

Watch mode exits `0` when interrupted, whatever the most recent verdict was. A
long-running stream has no single final verdict to report.

Use a single-shot run in CI:

```sh
tsacl --indeterminate=fail --file acl.hujson test
```

Exit `2` still signals the watcher's *own* failures — an unreadable `--file`,
a non-positive `--interval`, or an inapplicable flag combination. A policy that
is temporarily invalid mid-edit is none of those: it logs once to stderr and
the loop keeps running.

## Related

- [Why watch mode behaves the way it does](../explanation/watch-mode.md)
- [Exit codes](../reference/exit-codes.md)
- [Offline evaluation and safety](../explanation/offline-evaluation.md)
