# Adopt tsacl for an existing tailnet

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
tsacl --file acl/acl.hujson pull
```

`pull` writes the deployed bytes verbatim — comments, key order, and formatting
are preserved — and reports the ETag that identifies the version it fetched.
It also records that ETag in the gitignored `.tsacl-state.json` beside the
policy, keyed by tailnet.

`pull` refuses to overwrite an existing `--file`. If you have already started a
local policy and intend to discard it, pass `--force`; otherwise pull to a new
path and reconcile by hand.

## 2. Commit the untouched baseline

Commit the pulled file before editing it. A baseline commit that contains no
edits of your own makes the first real change reviewable as a diff against
what was actually deployed, rather than against nothing.

## 3. Confirm the local copy matches production

```sh
tsacl --file acl/acl.hujson plan
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
tsacl --file acl/acl.hujson grant add \
  --src group:eng --dst tag:ci --ip 22 \
  --comment "engineers reach CI over SSH"

tsacl --file acl/acl.hujson plan
```

Read the diff. `plan` validates the candidate as well as diffing it, so a
policy the control plane would reject fails here rather than at upload.

## 5. Upload with optimistic concurrency

```sh
tsacl --file acl/acl.hujson upload
```

`upload` defaults `If-Match` to the ETag the latest `plan` recorded, so it fails
rather than silently clobbering a change someone else made through the admin
console in the meantime. If it is rejected, pull the deployed policy to a
separate file, reconcile through the comment-preserving
`hujson-merge --base ... --add ...` path, review, re-plan, and retry. Do not use
`tsacl merge` for this recovery: its directory merge removes comments.

If the state file is absent or unreadable, upload refuses with exit `2`. Run
`plan` to recreate the observation, pass an explicit `--if-match ETAG`, or use
`--accept-remote-changes` to deliberately send no precondition. The last choice
can overwrite changes you have not seen and is never the default.

**`upload` replaces the entire deployed policy with `--file`.** It does not
merge a fragment into the live policy. Always plan a complete policy first.

## After adoption

Once the policy lives in version control, `pull` should be rare. The interactive
routine is edit → `test` → `lint` → `plan` → `upload`.

If a later `plan` shows drift you did not author, someone changed the policy
outside this workflow. Investigate before uploading — an upload would discard
their change wholesale.

## Related

- [Lint a policy](./lint-policy.md)
- [Exit codes](../reference/exit-codes.md)
- The [`tsacl` README](../../README.md) has the authoritative command and
  flag tables.
