# Add next-free allocation tasks

## 1. Gap-search primitive

- [x] 1.1 Implement family-safe interval and gap selection for the first free
  child prefix; verify valid and invalid input behavior with unit tests.
- [x] 1.2 Add table-driven tests for adjacency, containment, exhausted pools,
  mixed families, and a large sparse pool that proves selection avoids child
  materialization.

## 2. Integration verification

- [x] 2.1 Run policycore tests and the root repository gates to verify the
  exported primitive compiles for every dependent module.
