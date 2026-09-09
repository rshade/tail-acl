# Merge Specification

## Purpose

Compile ACL source fragments from one or more directories into one policy
file, using the shared HuJSON merge so comments and structure survive.

## Requirements

### Requirement: At least one --dir is required

The merge capability SHALL require at least one `--dir` and SHALL fail as a
usage error when none is supplied.

#### Scenario: No --dir is a usage error

- **WHEN** `merge` runs with no `--dir` flags
- **THEN** the command exits 2 and states that at least one `--dir` is
  required

### Requirement: Fragments from multiple directories are combined in order

The merge capability SHALL load every ACL fragment file from each `--dir` (in
the order given) and combine their top-level policy sections — including
grants, groups, postures, and `srcPosture` grant references — into one output
document written to `--file`.

#### Scenario: Grants from two directories are both present

- **WHEN** `--dir dir1` contributes a grant with `src: ["one"]` and
  `--dir dir2` contributes a grant with `src: ["two"]`
- **THEN** the merged policy at `--file` contains both grants

#### Scenario: A posture and its referencing grant round-trip together

- **WHEN** a fragment directory holds a `posture:labCompliant` definition and
  a grant whose `srcPosture` references it
- **THEN** the merged policy's `postures` map and the grant's `srcPosture`
  field both carry that reference

### Requirement: The result reports how many files were merged

The merge capability SHALL report the number of ACL fragment files it merged
in the envelope's `merged_files` field.

#### Scenario: Merged file count is reported

- **WHEN** `merge` combines fragments from two directories containing one
  file each
- **THEN** the result's `merged_files` field is `2`
