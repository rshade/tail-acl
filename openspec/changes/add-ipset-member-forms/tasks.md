# Tasks: add-ipset-member-forms

## 1. Member validation

- [x] 1.1 Add `IPSetMemberSpec` and `AddIPSetMembers` to `aclpolicy`, routing
  `--cidr` values through `NormalizeIPSetCIDR` and `--member` values through
  `policycore.ParseIPSetMember` plus host/ipset existence, self-reference, and
  cycle checks; keep `AddDefinition` delegating for the ipset kind
- [x] 1.2 Enforce `policycore.ValidateIPSetOperations` on the resulting set
  after idempotence filtering
- [x] 1.3 Unit tests for each member form, the missing host alias, the
  missing/self/cyclic ipset reference, the explicit-operation rule,
  idempotence, and unchanged `--cidr` behavior

## 2. Reference walks

- [x] 2.1 Teach `DefinitionReferences` and `collectReferences` to follow
  `ipset:` and `host:` references inside ipset members, with tests showing
  a nested-only definition is refused without `--force` and not reported
  unused

## 3. Lint

- [x] 3.1 Add `ipset-mixed-operations` (error) to the catalog and evaluate it
  over every ipset, with a test for a mixed set and a clean explicit set

## 4. CLI surface

- [x] 4.1 Register `--member` beside `--cidr` on `ipset add`, sharing one
  ordered member list; update the catalog summary, usage, and examples;
  regenerate and inspect the schema golden
- [x] 4.2 CLI test that `ipset add --member` writes an all-explicit set,
  rejects the mixed set, and is idempotent

## 5. Documentation

- [x] 5.1 README: `ipset add` row, usage example, member forms, the
  explicit-operation rule, the lint finding row, and the `check` caveat
