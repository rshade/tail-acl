# Tasks: add-ipset-member-forms

## 1. Member grammar

- [x] 1.1 Add `IPSetMember`, `IPSetOperation`, `IPSetMemberKind`, and
  `ParseIPSetMember` with canonical `String` rendering; unit tests for every
  form, canonicalization, and each rejection
- [x] 1.2 Add `ValidateIPSetOperations` and `IPSetImplicitMemberError`; unit
  tests for the mixed, all-explicit, and no-remove cases
- [x] 1.3 Document the API in `docs/public-api.md` and verify
  `go test ./...` and `golangci-lint run ./...` in the module
