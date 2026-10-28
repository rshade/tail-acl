# Tasks

## 1. Check

- [x] 1.1 Warn when a grant names a declared alias whose
  `allowIncomingConnections` is not true, and skip unknown aliases.

## 2. Tests

- [x] 2.1 Cover omitted, false, true, and unknown-alias cases.
- [x] 2.2 Regenerate the schema golden and read the diff.

## 3. Verify

- [x] 3.1 `openspec validate` and `go test` / `golangci-lint` for the
  packages this change touches.
