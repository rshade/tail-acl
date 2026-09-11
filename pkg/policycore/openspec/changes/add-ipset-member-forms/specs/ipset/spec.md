# ipset Member Grammar Delta

## ADDED Requirements

### Requirement: One ipset member parses into operation, kind, and canonical target

`ParseIPSetMember` SHALL accept one raw member and return its operation
(`add`, `remove`, or implicit), its kind, and its canonical target. A member
that is exactly one whitespace-separated field is implicit; exactly two fields
led by `add` or `remove` is an explicit operation on the second field; any
other shape SHALL be rejected. The target SHALL be classified as an `ipset:`
reference (non-empty name, kept as written), a `host:` alias (non-empty
alias, kept as written), an address range `A-B` (both ends addresses of one
family without zones, `A` not after `B`, rendered from the parsed ends), a
CIDR prefix (rendered masked), or a bare address without a zone (rendered
canonically), in that order. `IPSetMember.String` SHALL render the operation
word, when present, followed by a space and the canonical target.

#### Scenario: A remove operation on a CIDR is canonicalized

- **WHEN** `ParseIPSetMember("remove  10.1.2.3/16")` is called
- **THEN** it returns operation `remove`, kind prefix, target `10.1.0.0/16`,
  and `String` renders `remove 10.1.0.0/16`

#### Scenario: A range keeps its ends in order

- **WHEN** `ParseIPSetMember("10.0.0.9-10.0.0.1")` is called
- **THEN** it returns an error naming the range as starting after it ends

#### Scenario: An unknown operation word is rejected

- **WHEN** `ParseIPSetMember("drop 10.0.0.0/8")` is called
- **THEN** it returns an error naming `drop` as an unsupported operation

#### Scenario: A bare address is not promoted to a prefix

- **WHEN** `ParseIPSetMember("2001:DB8::1")` is called
- **THEN** it returns kind prefix with target `2001:db8::1`

### Requirement: A remove operation requires every member to be explicit

`ValidateIPSetOperations` SHALL return nil for a member list that contains no
`remove` operation, or whose every member is an explicit `add` or `remove`
operation. When the list contains a `remove` operation and any member that is
not an explicit operation, it SHALL return an `IPSetImplicitMemberError`
naming the first such implicit member and the first `remove` member, whose
message says to write the implicit member as `add <member>`.

#### Scenario: An implicit member beside a remove is reported

- **WHEN** `ValidateIPSetOperations([]string{"ipset:base", "remove 10.1.0.0/16"})`
  is called
- **THEN** it returns an `IPSetImplicitMemberError` with member `ipset:base`
  whose message contains `add ipset:base`

#### Scenario: Implicit members without a remove are fine

- **WHEN** `ValidateIPSetOperations([]string{"ipset:base", "add 10.0.0.0/8"})`
  is called
- **THEN** it returns nil
