# Edit Delta

## ADDED Requirements

### Requirement: Identity sanitization hides edited host, login, and route values

With `--sanitize identity`, human and JSON `message` text for `host set`,
`tag-owner add`, and `auto-approver add` or `remove` SHALL omit every
hostname, IP address, login, and route CIDR that command edited. The same
omission SHALL hold on the no-op path. Group, tag, ipset, and posture names
SHALL stay visible at `identity`.

#### Scenario: A host set hides the alias and address

- **WHEN** `host set SecretDB 100.64.0.10` runs with `--sanitize identity`,
  including a repeat that reports the host already set
- **THEN** neither human nor JSON output contains `SecretDB` or
  `100.64.0.10`, and the file path is a path placeholder

#### Scenario: A tag-owner add hides the login and keeps the tag

- **WHEN** `tag-owner add tag:SecretTag carol@example.com` runs with
  `--sanitize identity`, including a repeat that reports the owner already
  present
- **THEN** neither human nor JSON output contains `carol@example.com`, and
  both still contain `tag:SecretTag`

#### Scenario: An auto-approver edit hides the route CIDR

- **WHEN** `auto-approver add` or `remove` names `--route 10.30.0.0/16` with
  `--sanitize identity`, including a no-op
- **THEN** neither human nor JSON output contains `10.30.0.0/16`

### Requirement: Strict sanitization hides edited operational names

With `--sanitize strict`, human and JSON `message` text SHALL also omit the
group, ipset, posture, and tag names a `group`, `ipset`, `posture`, or
`tag-owner` mutation edited, on both the changed path and the no-op path.
`identity` SHALL keep those names visible.

#### Scenario: Group, ipset, and posture names survive identity only

- **WHEN** `group add` or `remove`, `ipset add` or `remove`, and
  `posture set` or `remove` run at `identity` and again at `strict`,
  including the no-op path for each
- **THEN** `identity` output still contains the edited `group:`, `ipset:`,
  or `posture:` name, and `strict` output does not

#### Scenario: A tag name is hidden at strict

- **WHEN** `tag-owner add tag:SecretTag carol@example.com` runs with
  `--sanitize strict`
- **THEN** neither human nor JSON output contains `tag:SecretTag` or
  `carol@example.com`

### Requirement: Unsanitized mutation messages keep their wording

With sanitization off, the `message` text of these mutations SHALL be
unchanged, and the JSON envelope SHALL NOT gain a field for the registered
identities.

#### Scenario: Host set without sanitization still names the host

- **WHEN** `host set SecretDB 100.64.0.10` runs without `--sanitize`
- **THEN** the JSON `message` contains `SecretDB` and `100.64.0.10`, and
  the envelope has no field that carries the registered identity list
