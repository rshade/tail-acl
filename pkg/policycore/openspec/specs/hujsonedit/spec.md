# Hujsonedit Specification

## Purpose

Provide schema-agnostic, comment-preserving RFC 6902 edits to HuJSON
documents — build `PatchOperation` values and apply them to a file or to an
in-memory document — carrying no knowledge of any particular document's
fields.

## Requirements

### Requirement: A patch either fully applies or leaves the document untouched

`PatchBytes` SHALL apply every operation in order and then author every
comment, returning the reformatted result, without ever mutating its input
byte slice. If any operation or comment fails, `PatchBytes` SHALL return no
document. `WritePatch` SHALL write the file atomically, and if `PatchBytes`
fails, the on-disk file SHALL remain byte-for-byte unchanged.

#### Scenario: A rejected comment leaves the file unmodified

- **WHEN** `WritePatch` is called with a `PatchComment` whose text contains a
  newline
- **THEN** it returns an error and the file on disk is unchanged from before
  the call

#### Scenario: PatchBytes does not mutate its input

- **WHEN** `PatchBytes` is called on a byte slice with `PatchAdd`
- **THEN** the caller's original slice is unchanged afterward, and the
  returned patched document is a separate value

### Requirement: WritePatch and PatchBytes produce byte-identical output

For the same starting document and the same operations, `WritePatch` SHALL
write to disk exactly the bytes `PatchBytes` returns, since `WritePatch` is
defined as `PatchBytes` bracketed by a read and an atomic write.

#### Scenario: Add, remove, and comment operations agree between the two entry points

- **WHEN** the same document and the same `PatchAdd`/`PatchRemove`/`PatchComment`
  operations are run once through `PatchBytes` and once through `WritePatch`
- **THEN** the bytes `WritePatch` wrote to disk equal the bytes `PatchBytes`
  returned

### Requirement: Comments append after existing ones, skip exact duplicates, or overwrite

`PatchComment` SHALL author its trimmed text as a leading `//`-prefixed line comment
on the target node, appended after any comments already there, unless that
exact trimmed text is already present, in which case it SHALL be skipped.
`PatchCommentOverwrite` SHALL instead replace every comment already
attached to that node with the new text. Comment text SHALL be validated by
`ValidateCommentText`, which SHALL reject empty or whitespace-only text, text
containing a carriage return or newline, and invalid UTF-8.

#### Scenario: An identical comment is not duplicated

- **WHEN** a node already carries the comment `"already here"` and
  `PatchComment("already here", …)` is applied to it
- **THEN** `LeadingComments` still reports exactly one comment on that node

#### Scenario: PatchCommentOverwrite replaces every existing comment

- **WHEN** a node carries two comment lines and `PatchCommentOverwrite("new
  note", …)` is applied
- **THEN** `LeadingComments` reports exactly one comment, `"new note"`

### Requirement: LeadingComments reports no comments for an absent node, never an error

`LeadingComments` SHALL return `nil` and no error when the node at the given
segments does not exist in the document, since nothing is there yet to carry
a comment; it SHALL return an error only when a segment indexes into
something that cannot be indexed (a literal, or an out-of-range array
position via an operation).

#### Scenario: An absent node reports no comments and no error

- **WHEN** `LeadingComments` is called on a segment path that does not exist
  in the document
- **THEN** it returns `(nil, nil)`

### Requirement: ResolveKey bridges an aliased top-level key before every access

When a non-nil `ResolveKey` is supplied, `WritePatch`, `PatchBytes`, and
`LeadingComments` SHALL apply it to the first path segment of every
operation and comment before resolving that segment against the document,
letting a caller's schema alias a legacy-cased top-level key without
changing how operations are authored.

#### Scenario: An operation resolves through an aliased top-level key

- **WHEN** a document spells its top-level key `"Foo"` and a `resolve`
  function maps the canonical `"foo"` to `"Foo"` when present, and
  `WritePatch` is called with `PatchAdd(value, "foo", "nested")`
- **THEN** `resolve` is invoked and the value is written under `/Foo/nested`
