# `/acl/validate` fixture provenance

This directory is the evidence gate for issue #52. Probes A, B, B-prime, D,
and E were captured from a maintainer-controlled tailnet on 2026-07-31 through
`integration/TestLiveValidateEvidenceGate`. Credentials came from the Pulumi
ESC environment used by the tailnet's deployment; neither credential value is
stored here. Probe C was unavailable because that environment did not identify
an unsynced SCIM group. No warning-channel shape is inferred from its absence.

The harness derived one real user from the deployed policy without printing or
persisting it. Exact byte substitution changed that identity to `<user-1>` in
the request manifest and response files. The tailnet name would likewise have
become `<tailnet>` if it had appeared in a captured body. All other response
bytes are verbatim.

## Capture procedure

Use a read-only API token on a scratch tailnet. When `TSACL_LIVE_USER` is
omitted, the harness derives a concrete email selector from the deployed policy
through the allowed `GET .../acl` request without printing or persisting it. Set
it explicitly when the policy contains no concrete users. Set the optional SCIM
group only when it is known to be unmanaged or unsynced on that tailnet:

```sh
export TAILSCALE_API_KEY=...
export TAILSCALE_TAILNET=...
export TSACL_LIVE_USER=alice@example.com # optional when present in the policy
export TSACL_LIVE_SCIM_GROUP=group:unknown@example.com # optional probe C
TSACL_LIVE=1 TSACL_CAPTURE=1 \
  go test ./integration/ -run LiveValidateEvidenceGate -v
```

`TSACL_LIVE=1` is a mandatory opt-in. The CLI reads ambient
`TAILSCALE_API_KEY` and `TAILSCALE_TAILNET`, so credentials alone must never
cause `go test ./...` to contact the control plane. The test transport fails
closed on anything other than `POST .../acl/validate` and `GET .../acl`.
Neither permitted endpoint changes the deployed policy.

The capture run writes:

- `validate_<scenario>.json`: response bytes exactly as received, except for
  placeholder substitution of the configured user, SCIM group, and tailnet name.
  Matching folds ASCII case, because the control plane normalizes logins and
  echoes them back lowercased while `TSACL_LIVE_USER` may be set in any case.
  A configured value shorter than four bytes aborts the run instead of being
  substituted: the v2 client's default tailnet `-` occurs inside ordinary probe
  text such as `not-a-user-or-host`, so replacing it would corrupt evidence
  while redacting nothing. Empty responses remain zero-byte files; `{}` and
  `{}\n` remain distinct.
- `validate_capture_manifest.json`: redacted request bodies, HTTP status,
  request and response content types, response byte counts, SHA-256 hashes, and
  derived key-shape summaries. Probe C records an explicit unavailable reason
  when `TSACL_LIVE_SCIM_GROUP` is unset.

After substituting, the harness scans the redacted bytes for anything
email-shaped and aborts on a hit, reporting only the offset and length so the
leak is not itself printed. That check exists because re-searching for a value
just substituted proves nothing — substitution always removes every occurrence
of what it was given. What it does catch is an identity the harness was never
told about: a SCIM group member, a device owner, or a login the server names in
prose rather than in `data[].user`.

It does not replace review. Read the files before committing them, and confirm
that no real identity remains while key presence, ordering, whitespace, `null`
versus `[]`, and absent versus empty values are unchanged. The manifest hash
covers the redacted bytes that are committed, not the sensitive original;
`TestCaptureManifestMatchesCommittedFixtures` re-derives each hash and byte
count from the committed file, so a later hand-edit fails the build rather than
silently invalidating the provenance record.

## Probe matrix and determination

| Probe | Scenario | Required outcome record |
| --- | --- | --- |
| A | Tests-array mode, contradictory accept and deny | Status, content type, verbatim redacted body |
| B | Policy-object mode, genuine failing deny assertion | Status, content type, verbatim redacted body |
| B-prime | Policy-object mode, unknown source | Status, content type, verbatim redacted body |
| C | Unsynced SCIM group | Capture warning response, or explicitly retain unavailable |
| D | Syntactically invalid HuJSON | Status, content type, verbatim body |
| E | Healthy minimal policy | Distinguish empty body, `{}`, and any newline exactly |

## Determination

The data-only hypothesis did **not** reproduce on any reachable path:

- A and B returned HTTP 200 with `message: "test(s) failed"` and one populated
  `data` entry carrying the failing assertion.
- B-prime returned HTTP 200 with the same non-empty message and a populated
  `data` entry carrying `user or host is invalid`.
- D returned HTTP 200 with a non-empty parse-error message and absent `data`.
- E returned HTTP 200 and exactly two response bytes: `{}` with no newline.

Accordingly, these captures do not evidence a current control-server response
with empty or absent `message` and non-empty `data`. The fake-server data-only
case remains valuable as a fail-closed guard against an undocumented response
change. Probe C remains explicitly unavailable, so this run neither confirms
nor disproves the documented warnings-only channel. Defects 2 and 3 therefore
remain independent reasons to preserve warnings and typed per-user detail at
the client boundary.
