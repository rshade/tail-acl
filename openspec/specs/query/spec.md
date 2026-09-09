# Query Specification

## Purpose

Query the policy with the embedded jq engine (the `jq` subcommand): standardize
the HuJSON policy, evaluate one jq PROGRAM with gojq, and report matched
values.

## Requirements

### Requirement: Human output streams NDJSON; JSON output buffers into the envelope

The query capability's human format SHALL stream one JSON value per line as
gojq yields it. Its `-format json` SHALL instead buffer every value and emit
them under the envelope's `results` key, since the envelope cannot stream.

#### Scenario: Human output is one value per line

- **WHEN** `jq '.grants[].src[]'` runs with human output against a policy
  whose grants have `src` values `group:dev` and `tag:ci`
- **THEN** stdout is exactly those two JSON strings, one per line, with no
  summary line

#### Scenario: JSON output wraps the same values in results

- **WHEN** the same query runs with `-format json`
- **THEN** stdout is one envelope whose `results` array holds
  `["group:dev", "tag:ci"]`

### Requirement: An empty match set is success, not failure

The query capability SHALL treat a query that matches nothing as
`status: ok` with an empty `results` array, not as an error.

#### Scenario: No matches still emits an empty array

- **WHEN** `jq '.grants[] | select(false)' -format json` runs
- **THEN** stdout contains `"results": []` and the command exits 0

### Requirement: Large integers keep exact precision

The query capability SHALL decode the policy with `json.Number` rather than
`float64`, so an integer value larger than 2^53 (such as a routeID) round-trips
exactly through a query.

#### Scenario: A routeID above 2^53 is not rounded

- **WHEN** a query selects a `routeID` field holding `9007199254740993`
- **THEN** the printed value is exactly `9007199254740993`

### Requirement: A malformed program or mid-run evaluation error is a usage error

The query capability SHALL exit 2 for a jq PROGRAM that fails to parse, and
SHALL also exit 2 when gojq raises an error partway through evaluation, in
each case without ever writing to the JSON-format envelope.

#### Scenario: Unparseable program exits 2 with empty stdout

- **WHEN** `jq '.grants['` runs (an unbalanced program)
- **THEN** the command exits 2 and stdout is empty

#### Scenario: Mid-stream error truncates human output but not JSON output

- **WHEN** a program yields values before failing and human output is
  requested
- **THEN** the values produced before the failure are already on stdout, the
  command exits 2, and `-format json` for the same program instead leaves
  stdout empty

### Requirement: Active sanitization is refused

The query capability SHALL refuse to run under a non-off `--sanitize` level,
because query results drawn from policy content cannot be mechanically
sanitized.

#### Scenario: Sanitize strict is rejected

- **WHEN** `jq '.'` runs with `--sanitize strict`
- **THEN** the command exits 2 and states that its output cannot be
  mechanically sanitized
