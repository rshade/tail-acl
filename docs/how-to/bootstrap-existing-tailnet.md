# Adopt tail-acl for an existing tailnet

This guide moves a policy that was authored in the Tailscale admin console
under local, reviewable control, without a window in which your file and the
deployed policy disagree.

Use it once per tailnet. It is an adoption procedure, not a synchronization
loop.

## Before you start

Provide credentials for a tailnet you are permitted to change:

```sh
export TAILSCALE_TAILNET=example.com
export TAILSCALE_API_KEY=tskey-api-...
```

Every step below except the final upload is read-only.

## 1. Pull the deployed policy

```sh
tail-acl --file acl/acl.hujson pull
```

`pull` writes the deployed bytes verbatim — comments, key order, and formatting
are preserved — and reports the ETag that identifies the version it fetched.
Record that ETag.

`pull` refuses to overwrite an existing `--file`. If you have already started a
local policy and intend to discard it, pass `--force`; otherwise pull to a new
path and reconcile by hand.

## 2. Commit the untouched baseline

Commit the pulled file before editing it. A baseline commit that contains no
edits of your own makes the first real change reviewable as a diff against
what was actually deployed, rather than against nothing.

## 3. Confirm the local copy matches production

```sh
tail-acl --file acl/acl.hujson plan
```

`plan` fetches the deployed policy and prints a validated unified diff without
applying anything. Immediately after a clean `pull`, that diff should be empty.

An empty diff is the signal that adoption succeeded. A non-empty diff here
means the policy changed between your pull and your plan, or that the file was
edited before this check — resolve that before continuing.

## 4. Make the first change and plan it

Edit the policy with the authoring commands rather than by hand, so the file
keeps its comments and stays well-formed:

```sh
tail-acl --file acl/acl.hujson grant add \
  --src group:eng --dst tag:ci --ip 22 \
  --comment "engineers reach CI over SSH"

tail-acl --file acl/acl.hujson plan
```

Read the diff. `plan` validates the candidate as well as diffing it, so a
policy the control plane would reject fails here rather than at upload.

## 5. Upload with optimistic concurrency

```sh
tail-acl --file acl/acl.hujson upload --if-match "<etag-from-step-1>"
```

`--if-match` makes the upload fail rather than silently clobber a change
someone else made through the admin console in the meantime. Re-pull, re-plan,
and retry if it is rejected.

**`upload` replaces the entire deployed policy with `--file`.** It does not
merge a fragment into the live policy. Always plan a complete policy first.

## After adoption

Once the policy lives in version control, `pull` should be rare. Routine work
is edit → `test` → `lint` → `plan` → `upload`, gated in CI. See
[Gate policy changes in CI](../../../docs/how-to/gate-policy-changes-in-ci.md).

If a later `plan` shows drift you did not author, someone changed the policy
outside this workflow. Investigate before uploading — an upload would discard
their change wholesale.

## Related

- [Lint a policy](./lint-policy.md)
- [Exit codes](../reference/exit-codes.md)
- The [`tail-acl` README](../../README.md) has the authoritative command and
  flag tables.
