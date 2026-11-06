# Repository Guidelines

## Project Structure & Module Organization

`github.com/rshade/tsacl` is a single Go module with two products:

- `cmd/tsacl` is the CLI.
  Treat `tsacl`'s commands, flags, exit codes, and output as compatibility
  contracts.
- `pkg/policycore/...` is the public library (`addrspace`, `cliflags`,
  `hujsonedit`, `posture`, `sanitize`) that other tools import, and
  `pkg/ipcalc` is the policy-agnostic subnet arithmetic library. Treat their
  exported APIs as compatibility contracts too.

`internal/` holds the CLI's private packages, `integration/` the end-to-end
tests, and `docs/` the guides. Tests sit beside the code as `*_test.go`;
fixtures belong in `testdata/`. Do not add a `go.mod` under `pkg/` without
deciding to version `policycore` separately.

## Build, Test, and Development Commands

Tool versions and tasks live in `mise.toml`; CI runs the same tasks.

```bash
mise install          # install the pinned toolchain
mise run build        # go build ./...
mise run test         # go test ./...
mise run vet          # go vet, including -tags live_verify
mise run cross        # compile for linux, darwin, windows
mise run lint         # every check
mise run apidiff      # incompatible pkg/ changes since origin/main
```

`mise run lint` covers golangci-lint, gofmt, `go mod tidy`, the Go version pin,
markdownlint, actionlint, commitlint, govulncheck, the dependency license
allowlist, and both secret scanners. Run a single test with
`go test -run TestName ./path/to/pkg`.

## Coding Style & Naming Conventions

Format Go with `gofmt -s`/`goimports` and follow standard Go naming. The
`.golangci.yml` enforces strict shadowing and parallel tests; every test should
call `t.Parallel()`. Any `//nolint:<linter>` must include a reason. CLI results
belong on stdout and diagnostics on stderr; keep JSON and NDJSON parse-clean.
Follow [`docs/reference/ax-conventions.md`](docs/reference/ax-conventions.md).

## Testing Guidelines

Use Go's `testing` package and descriptive `TestXxx` names. Add regression tests
for behavior changes and run `mise run test lint cross` before review. Golden
files are byte-exact: regenerate with `go test ./... -update`, then inspect every
changed fixture. Preserve authentic bytes under `testdata/`.

The `live_verify` build tag and the `TSACL_LIVE=1` opt-in gate credentialed,
read-only tests against a real, shared tailnet. They never run in ordinary CI;
the `Live verify` workflow compiles them on PRs and runs them only on manual
dispatch from `main`, after approval.

## Editing Conventions

Every `remove` command ends with `PatchPruneEmpty` for the container it
emptied, so add-then-remove restores the original file shape. The prune skips
any container that carries a comment, so authored text is never deleted with
its last entry. `tsacl merge --dir` writes standard JSON and strips comments;
`tsacl merge --base --add` keeps them and is the stale-ETag reconciliation
path. `tsacl` is the only shipped binary.

## Spec-Driven Changes (OpenSpec)

A change that adds or alters a capability, CLI surface, or machine-readable
output goes through OpenSpec (`openspec/`, and `pkg/policycore/openspec/` for the
library) before implementation. A contained fix does not. Specs describe
behavior that exists; archive a change once its PR merges.

## Commit & Pull Request Guidelines

Use Conventional Commits; commitlint checks every PR commit. release-please
reads them to cut `vX.Y.Z` releases, so a breaking change needs `feat!:` or a
`BREAKING CHANGE:` footer. A deliberate break to `pkg/` also needs the
`breaking-change-approved` label, which the API Diff check requires.

## Security

Never commit credentials, real tailnet names, or real email addresses. Use
`example.com` and `example.ts.net` in fixtures. Live uploads require explicit
authorization. See [`SECURITY.md`](SECURITY.md).

`pkg/policycore/sanitize` hashes the literal `tailscale-utils/sanitize/v1` as a
domain-separation tag. Do not rename it; doing so changes every sanitized output.
