# Tasks

## 1. Check

- [x] 1.1 Add `external-tailnet-alias-unknown` and recognize
  `group://` / `tag://` before the local group and tag checks, including
  before ACL destination port stripping.

## 2. Tests

- [x] 2.1 Unknown grant source, declared alias, and `tag://` not reported
  as `dst-tag-no-owner`.
- [x] 2.2 Regenerate the schema golden and read the diff.

## 3. Verify

- [x] 3.1 `openspec validate lint-external-tailnet-alias` and
  `go test` plus `golangci-lint run` for `internal/aclpolicy` and
  `cmd/tail-acl`.
