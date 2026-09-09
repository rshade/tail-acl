# Validate Specification

## Purpose

Validate the policy file via the Tailscale API's authoritative
`/acl/validate` endpoint, read-only.

## Requirements

### Requirement: Credentials and tailnet are required

The validate capability SHALL exit 2 and name the missing `TAILSCALE_TAILNET`
(or API key/OAuth credential) when a required credential or the tailnet is
not supplied.

#### Scenario: Missing tailnet is a usage error

- **WHEN** `validate` runs with no `--tailnet` and no `TAILSCALE_TAILNET`
- **THEN** the command exits 2 and the error names `TAILSCALE_TAILNET`

### Requirement: The result is a three-state verdict

The validate capability SHALL report `status: ok` when the control plane
returns a clean result, `status: failed` when it rejects the policy, and
`status: indeterminate` when the response cannot be read as a verdict
(warnings with no errors alongside a message, or a detail with neither
errors nor warnings).

#### Scenario: A clean policy is reported valid

- **WHEN** the control plane returns a validate response with no errors or
  warnings
- **THEN** the result is `status: ok` and the message states the file is
  valid

### Requirement: A control plane that never judges the policy prints no verdict

The validate capability SHALL exit 2 without printing any result envelope
when the control plane request fails outright (authentication, rate
limiting, a server fault, or an unreachable API) rather than reporting the
policy as invalid.

#### Scenario: An unreachable API prints nothing

- **WHEN** the configured API URL is unreachable
- **THEN** `validate` exits 2 and writes no result to stdout

### Requirement: OAuth credential class is reported without the secret

The validate capability SHALL report
`authentication: "oauth_client_credentials"` in the envelope when OAuth
client credentials are used, and SHALL never include the client secret in
output.

#### Scenario: OAuth authentication is named, not the secret

- **WHEN** `validate` runs with `--oauth-client-id`/`--oauth-client-secret`
  set
- **THEN** the envelope's `authentication` field is
  `"oauth_client_credentials"` and stdout contains no client secret
