# Cliflags Specification

## Purpose

Adapt stdlib-flag-era command lines to pflag/cobra parsing by rewriting
single-dash long flags into pflag's double-dash form, so a tool migrated from
stdlib `flag` keeps both spellings working.

## Requirements

### Requirement: Single-dash long flags are rewritten across the whole command tree

The cliflags capability SHALL rewrite a single-dash argument into its
double-dash form when its name (before any `=value`) matches a long flag
registered anywhere in the command tree rooted at the given command,
including a subcommand's own flags and cobra's lazily-registered `help`
flag. A one-character name SHALL be left for pflag's own shorthand handling,
and an inline `=value` SHALL be preserved.

#### Scenario: A subcommand's flag is rewritten

- **WHEN** `Normalize` is given `["lint", "-severity", "error"]` against a
  root command whose `lint` subcommand registers a `severity` flag
- **THEN** it returns `["lint", "--severity", "error"]`

#### Scenario: A single-character argument is left for shorthand handling

- **WHEN** `Normalize` is given `["-v"]`
- **THEN** it returns `["-v"]` unchanged

### Requirement: Unregistered arguments and the "--" terminator are left untouched

The cliflags capability SHALL leave an already-double-dash argument, an
unregistered dash-prefixed token, and every argument at or after a bare `--`
terminator unrewritten, and SHALL NOT mutate its input slice.

#### Scenario: Arguments after "--" survive verbatim even if flag-shaped

- **WHEN** `Normalize` is given `["-format", "json", "--", "-format", "raw"]`
- **THEN** it returns `["--format", "json", "--", "-format", "raw"]`, leaving
  the operand after `--` unrewritten

#### Scenario: The input slice is not mutated

- **WHEN** `Normalize` is called with `["-format", "json"]`
- **THEN** the caller's original slice still reads `["-format", "json"]`
  afterward
