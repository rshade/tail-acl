# Gate policy changes in CI

Use `tail-acl` in two stages: fast offline checks for every proposed change,
then authoritative control-plane validation before deployment.

## Run offline checks on pull requests

Install a fixed `tail-acl` version in the job, then run:

```bash
tail-acl --file policy.hujson lint
tail-acl --indeterminate=fail --file policy.hujson test
```

`--indeterminate=fail` turns an unprovable local assertion into exit `1`, which
prevents the job from treating incomplete evidence as success. These commands
need no API credentials.

## Validate after merge

Expose the API token only to a protected deployment job:

```bash
export TAILSCALE_API_KEY="${TAILSCALE_API_KEY_FROM_SECRET_STORE}"
export TAILSCALE_TAILNET=example.com
tail-acl --file policy.hujson validate
tail-acl --file policy.hujson plan
```

Review or capture the plan output according to your deployment process.

## Protect the upload

Pass the opaque ETag returned for the deployed policy back to the upload:

```bash
tail-acl --file policy.hujson --if-match '"etag-from-plan"' upload
```

An ETag mismatch means the deployed policy changed after the plan. Stop the job,
pull the current policy, reconcile it, and rerun the checks. Do not retry by
dropping `--if-match`.

For structured evidence, add `--format json` and archive stdout separately from
stderr so diagnostics never corrupt the JSON document.

See the [`tail-acl` documentation](../README.md) for its exact
exit and output contracts.
