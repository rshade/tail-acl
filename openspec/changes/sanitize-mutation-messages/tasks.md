# Tasks

## 1. Register edited identities

- [x] 1.1 Replace `EditedAlias` with `Edited []editedValue` (`json:"-"`) on
  `result`, register the slice in `registerResultIdentities`, and update
  `TestSanitizedOutputTypesRequireExplicitFieldDecisions`. Verify the field
  guard test compiles and lists `Edited` rather than `EditedAlias`.
- [x] 1.2 Point `external-tailnet add` and `remove` at the shared slice and
  delete `EditedAlias`. Verify `TestExternalTailnetMutationsSanitizeAlias`
  still passes.

## 2. Mutation messages

- [x] 2.1 Record the edited name on `group` and `ipset` add/remove, the owner
  and tag on `tag-owner add`, the alias and address on `host set`, the
  posture name on `posture set` and `remove`, and the route CIDR on
  `auto-approver add` and `remove`, including each no-op return. Verify with
  a table test of those commands at `identity` and `strict`, human and JSON,
  changed and no-op: `sanitizetest.AssertNoIdentityLeaks` for values that
  level must hide, operational names still present at `identity`, and the
  file path absent. Also verify unsanitized `host set` JSON still contains
  the alias and address and does not serialize `Edited`.

## 3. Verify

- [x] 3.1 From `tsacl`, run `openspec validate sanitize-mutation-messages --strict`
  and `GOWORK=off go test ./...`, then `golangci-lint run ./...`. From the
  worktree root, run `make test` and `make lint` when time allows.
