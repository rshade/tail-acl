# Test Delta

## ADDED Requirements

### Requirement: Assertions over ipset member forms evaluate against the materialized set

The test capability SHALL evaluate an `accept` or `deny` assertion whose
path reaches an ipset by the set's materialized address space — operations
applied in order, ranges expanded, `host:` references resolved — so an
`accept` of an address the set keeps passes and a `deny` of it fails, and
SHALL treat an assertion whose path reaches a defined ipset that cannot be
materialized as indeterminate under the `--indeterminate` policy rather
than as a passing `deny`.

#### Scenario: An accept inside a trimmed set passes and a deny of it fails

- **WHEN** a grant permits `tag:web` to `ipset:trimmed` (`["add 10.0.0.0/8",
  "remove 10.1.0.0/16"]`) on `tcp:80`, and `tests[]` asserts `accept:
  ["10.2.0.5:80"]` and `deny: ["10.2.0.5:80"]` for `src: tag:web`
- **THEN** the `accept` assertion reports `PASS` and the `deny` assertion
  reports `FAIL`
