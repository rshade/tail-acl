# Edit Specification

## Purpose

Make typed, comment-preserving edits to a Tailscale policy file: `init`,
`grant`, `group`, `ipset`, `ssh`, `nodeattr`, `tag-owner`, `host`, `posture`,
and `auto-approver` add/remove subcommands, each acting on one policy element.

## Requirements

### Requirement: Typed edits preserve comments and formatting

The edit capability SHALL apply every add/remove as a JSON Patch operation
against the source bytes, preserving HuJSON comments, formatting, and unknown
top-level members in both JSON and HuJSON files.

#### Scenario: Unrelated comments survive a grant edit

- **WHEN** `grant add`, `tag-owner add`, `host set`, and `posture set` run in
  sequence against a HuJSON file carrying hand-written `ssh`/`sshTests`
  comments and extensions
- **THEN** the ssh block and its comments remain byte-for-byte unchanged after
  every edit

### Requirement: Add operations are idempotent

The edit capability SHALL treat adding an already-present element (by its
semantic identity, not array position) as a no-op that reports
`status: no_changes` rather than duplicating it.

#### Scenario: Repeating a grant add changes nothing

- **WHEN** `grant add --src autogroup:member --dst tag:web --ip tcp:443` runs
  twice against the same file
- **THEN** the policy holds exactly one matching grant after both runs

#### Scenario: Repeating a tag-owner add changes nothing

- **WHEN** `tag-owner add tag:web autogroup:admin` runs twice
- **THEN** `tag:web` has exactly one owner, `autogroup:admin`

### Requirement: Remove validates its target before writing

The edit capability SHALL reject a `grant remove --index` or `nodeattr
remove --index` outside the current array bounds without modifying the file,
and SHALL require `--force` to remove a `group` or `ipset` still referenced
elsewhere in the policy.

#### Scenario: Out-of-range grant index is rejected

- **WHEN** `grant remove --index 5` runs against a policy with fewer than 6
  grants
- **THEN** the command exits 2, names the valid range, and the file is
  unchanged

### Requirement: Comments can be authored or overwritten explicitly

The edit capability SHALL accept `--comment TEXT` on authoring subcommands to
attach a comment to the affected element, and SHALL require `--overwrite-comment`
to replace an existing comment rather than silently leaving it or erroring.

#### Scenario: --overwrite-comment without --comment is rejected

- **WHEN** an authoring subcommand is given `--overwrite-comment` but no
  `--comment`
- **THEN** the command exits 2 and states that `--overwrite-comment` requires
  `--comment`

### Requirement: Init bootstraps the smallest valid policy

The edit capability's `init` subcommand SHALL write the minimal valid policy
document (`{}` followed by a newline) to `--file` and SHALL refuse to
overwrite an existing file.

#### Scenario: Second init is refused

- **WHEN** `init` runs twice against the same `--file`
- **THEN** the first run creates `{}\n`, and the second exits with a
  "refusing to overwrite" error leaving the file unchanged
