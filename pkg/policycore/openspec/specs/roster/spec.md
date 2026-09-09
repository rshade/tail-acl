# Roster Specification

## Purpose

Decode an operator-supplied login-to-role roster into the map `Matcher.Roles`
expects, accepting both the Tailscale users API envelope and a hand-authored
flat object, so role-autogroup resolution and roster loading can never
disagree about normalization.

## Requirements

### Requirement: Both roster shapes are accepted and logins are lowercased

The roster capability SHALL decode either the Tailscale users endpoint
envelope (`{"users":[{"loginName":…,"role":…}]}`, ignoring fields beyond
`loginName` and `role`) or a flat `{login: role}` object, sniffing the shape
from whether `"users"` holds a JSON array. Every login key in the returned
map SHALL be lowercased. A successful parse SHALL always return a non-nil
map, including for an empty roster, so an operator-confirmed empty roster
stays distinguishable from one that was never read.

#### Scenario: The envelope form ignores extra fields and lowercases logins

- **WHEN** `ParseRoster` is given
  `{"users":[{"loginName":"Ada@Example.COM","role":"admin","id":"u1"}]}`
- **THEN** it returns `{"ada@example.com": UserRoleAdmin}`, dropping the `id`
  field

#### Scenario: An empty flat map asserts a read roster with nobody in it

- **WHEN** `ParseRoster` is given `{}`
- **THEN** it returns a non-nil, empty map and no error

### Requirement: Every defect is rejected with a deterministic message

The roster capability SHALL reject invalid JSON, an unrecognized role
(naming the seven-role vocabulary the error accepts), an empty or
whitespace-only login, a non-string role, and a login that collides with
another only after lowercasing (naming both original spellings). Entries
SHALL be walked in sorted login order so a file carrying more than one defect
reports the same one on every run, since map iteration order is otherwise
randomized.

#### Scenario: A duplicate login after lowercasing names both spellings

- **WHEN** `ParseRoster` is given
  `{"Ada@example.com": "admin", "ada@example.com": "member"}`
- **THEN** it returns an error containing `appears twice` and naming both
  `"Ada@example.com"` and `"ada@example.com"`

#### Scenario: A roster with several defects reports the same one every run

- **WHEN** `ParseRoster` is given a roster with three different unknown-role
  entries and is called repeatedly
- **THEN** every call reports an error with the identical message, because
  entries are walked in sorted order rather than map iteration order
