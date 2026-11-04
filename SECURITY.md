# Security Policy

## Reporting a Vulnerability

Report suspected vulnerabilities privately through GitHub Security Advisories:

<https://github.com/rshade/tsacl/security/advisories/new>

Do not report vulnerabilities through public GitHub issues, pull requests, or
Discussions before coordinated disclosure.

Please include:

- The affected `tsacl` version, commit, or branch.
- A concise impact statement.
- Reproduction steps or a minimal proof of concept.
- Any relevant logs or output with API keys, tailnet names, and other personal
  data removed.
- Whether the issue is already public or being reported to other projects.

## Response Targets

The maintainer aims to:

- Acknowledge a complete private report within 72 hours.
- Provide an initial triage result within 7 calendar days.
- Send status updates at least every 14 calendar days until resolution or
  closure.

These are targets, not legal guarantees. Reports involving credential exposure,
a way to make `tsacl` upload a policy the operator did not approve, or a
bypass of the `--if-match` ETag guard are prioritized.

## Supported Versions

`tsacl` is pre-v1.0. Patch releases (`0.x.PATCH`) are backward-compatible and
are the preferred vehicle for security fixes. Minor releases (`0.MINOR.0`) may
contain breaking changes.

| Version line | Security support |
| ------------ | ---------------- |
| Latest `0.x` minor | Supported |
| Earlier minors | Not supported; upgrade to the latest minor |
| `main` / unreleased | Best effort |

## Disclosure Policy

`tsacl` follows coordinated disclosure. Keep vulnerability details private
until a fix or documented mitigation is available, unless there is active
exploitation. The default embargo target is up to 90 days from acknowledgment,
adjusted by mutual agreement for severity, patch complexity, and downstream
impact.

## Scope Notes

- `tsacl` reads a Tailscale API key or OAuth credentials from the
  environment. Reports about secrets reaching logs, error output, or the
  `.tsacl-state.json` file are in scope.
- `pkg/policycore` is a public library. Reports about it are in scope.
