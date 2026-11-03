# Plan: extract tail-acl and policycore into their own public repo

Status (2026-11-02): steps 0 to 3 are done, and step 4 is done up to the push.
This directory is now the new repository: the extracted history (112 commits)
plus two commits on top, `chore: rename module to github.com/rshade/tail-acl`
and `chore: add repository scaffolding`, with the old `tail-acl/v0.1.0` to
`v0.3.0` tags. The assembled tree passed every `mise run` check. Nothing has been
pushed, and the monorepo is untouched. Next is the push, which needs the user's
explicit go-ahead.

Local git identity here is `131337+rshade@users.noreply.github.com`. The global
identity is the personal address that the scrub removed, so a commit
made with it would put that address back into history.

Workday guard: on weekdays 07:30 to 17:30 Central, agent tool calls in this
directory are denied until the user runs `/workday OFF`. Plan work here for after
17:30 or after that override.

## Goal

Move `tail-acl` and `policycore` out of the `tailscale-utils` monorepo into a
new public repo, `github.com/rshade/tail-acl`, as a **single Go module**:

```text
github.com/rshade/tail-acl            (one go.mod)
├── cmd/tail-acl, cmd/acl-upload, cmd/hujson-merge
├── internal/...
├── integration/
└── pkg/policycore/...   addrspace, alpha, cliflags, hujsonedit, ipcalc,
                         posture, sanitize
```

Consumers import `github.com/rshade/tail-acl/pkg/policycore/<pkg>` and,
because Go compiles only imported packages, never build `tail-acl`-only
dependencies into their binaries.

## Findings from the current tree

- `policycore` is imported by `tail-acl`, `tail-ipam`, `tailnet-audit`,
  `tailnet-flow`, and `tailscale-doctor`, each through
  `replace github.com/rshade/tailscale-utils/policycore => ../policycore`.
- `tail-acl` and `policycore` import nothing else from the monorepo (no
  `tools`, no other tool modules).
- The only `../` reference out of either directory is one doc link in
  `tail-acl/docs/how-to/lint-policy.md` to
  `docs/how-to/gate-policy-changes-in-ci.md`.
- Existing tags: `tail-acl/v0.1.0`, `v0.2.0`, `v0.3.0`. There are none for
  `policycore`.
- About 96 files across `tail-acl` and `policycore` carry the old import
  paths, and about 50 more across the other four tools will need rewriting
  in step 5.
- `tail-acl/dist` (33 MB) is git-ignored and is not carried over.

## Dry-run results (2026-10-28)

Ran in a throwaway clone of `tailscale-utils` in the session scratchpad; the
real checkout and this directory were not touched.

- `git filter-repo` with the two `--path` and two `--path-rename` flags took
  about 0.2 s. Result: 112 commits, 4 MB tree, no `dist/` or report zips.
- Merging was a four-line `go.mod` change: new module path, drop the
  `policycore` `require` and `replace`. All shared dependency versions already
  matched, so nothing needed reconciling.
- A `sed` pass over 96 files rewrote the imports. `go mod tidy`,
  `go build ./...`, `go vet ./...`, and `go test ./...` all pass (17 packages,
  including `integration`).
- Dependency footprint of `./pkg/policycore/...` is 6 third-party modules,
  against 47 for the whole module. The 41 that only `tail-acl` pulls in
  include `go-git`, `viper`, `gojq`, and `tscli`. A `policycore` consumer's
  binary never builds them, but their requirements sit in the module graph.
  This is the cost of the single-module choice.
- Not exercised: the `live_verify` build tag (needs credentials) and the
  Windows-only files.

### History secret scan (2026-10-28)

Ran against the extracted history (112 commits, 3.4 MB), using
`mise exec trufflehog@3.99.4` with `--no-verification` (so no candidate
credential leaves the machine) and `mise exec aqua:gitleaks/gitleaks@8.30.1`.

- `trufflehog`: 0 findings.
- `gitleaks`: 2 findings, both `generic-api-key` on the same test sentinel
  (a `tskey-api-SE…` constant in
  `TestFlagErrorsDoNotPrintAPIKeyFromEnvironment`, in
  `cmd/acl-upload/main_test.go` and `cmd/tail-acl/main_test.go`, commit
  `3233567a`). A placeholder the test asserts is never printed; allowlist it
  in `.gitleaks.toml` rather than rewriting history.
- Still to scan by eye: `integration/testdata/.tail-acl-state.json` and
  `pkg/policycore/testdata/` for real tailnet names or IPs, which secret
  scanners do not flag.

### History scrub (2026-10-28)

Chosen: scrub both identifiers from the extracted history before publishing.
The exact files and commands are in step 1; the rules are:

- `<personal-email>` becomes `owner@example.com` (blobs and messages).
- `<lab-tailnet>.ts.net` becomes `example.ts.net`, then bare
  `<lab-tailnet>` becomes `example`.
- `--mailmap` maps the 21 commits authored as `<personal-email>` to
  `131337+rshade@users.noreply.github.com`. Every commit hash changes.
- Run `git filter-repo --force` on the already-extracted clone, then re-apply
  the import rewrite (the working-tree edits do not survive a rewrite).
- Result: 0 hits for either string in tree or history, 112 commits, tags
  `tail-acl/v0.1.0` to `v0.3.0` kept, 17 packages pass, Windows build passes,
  trufflehog 0 findings, gitleaks clean with `.gitleaks.toml`.
- `CHANGELOG.md` links point at private `tailscale-utils` commits and issues;
  decide whether to keep or strip them before going public.

### Scaffolding results (2026-10-28)

Assembled in a scratch tree and run through `mise run`: `go-version-check`,
`fmt-check`, `tidy-check`, `vet`, `build`, `test`, `cross`, `license-check`,
`release-check`, `lint-actions`, `lint-md`, `govulncheck`, `lint-go`,
`apidiff`, `scan-gitleaks`, `scan-trufflehog` all pass.

- **go-apidiff is broken on Go 1.27.3.** v0.8.3 prints nothing and exits 0 even
  when an exported function is removed (it works under Go 1.26.7). A gate built
  on it passes every break. `scripts/apidiff.sh` uses `golang.org/x/exp/cmd/apidiff`
  in export-file mode instead, tested against a removed function (reported) and
  an unchanged tree (silent). `ax-go` pins the same go-apidiff and Go version,
  so check whether its `apidiff` workflow is a silent no-op.
- **The import-path `sed` breaks `gofmt`.** Rewriting the paths changes import
  sort order, so `gofmt -s -l` flags about 20 files. `rewrite-imports.sh` now
  runs `gofmt -s -w .` before `go mod tidy`.
- **`jaxxstorm/vers`** (via `tscli`) says Apache-2.0 in its README but ships no
  `LICENSE`, so `go-licenses` cannot classify it. The `license-check` task
  ignores that one module, with a comment.
- **mise task bodies are templates.** `{{.GoVersion}}` in a `run` string is
  parsed as mise syntax; `go-version-check` reads `go.mod` with `awk` instead.
- **release-please needs a `v0.3.0` tag.** With `include-component-in-tag:
  false` it looks for `v0.3.0` as its baseline and will otherwise try to
  release the whole history. Push `v0.3.0` at the same commit as
  `tail-acl/v0.3.0` when publishing.

### Traps found

- `pkg/policycore/sanitize/sanitize.go` hashes the literal
  `tailscale-utils/sanitize/v1` as a domain-separation tag. **Do not rewrite
  it**; changing it changes sanitized output. Keep the import-rewrite `sed`
  scoped to the two exact module paths, never to a bare `tailscale-utils`.
- `NOTICE` said `tailscale-utils`; fixed by hand (step 2).
- The clone keeps the other tools' tags (`tail-ipam/v0.1.0`,
  `tailnet-audit/v0.1.0`, and so on); step 1 deletes them.
- `policycore` carried its own `.github/`, `.claude/`, and `.agents/`; they
  sit under `pkg/policycore/` and are inert. Step 2 deletes them.
- Real tailnet names and personal emails are invisible to secret scanners.
  Grep for them by hand before every publish.
- Editing `mise.toml` makes mise refuse to load it until `mise trust` is run, and
  the mise `python3` shim then fails; use `/usr/bin/python3` for scripts.
- Do not copy an older checkout of the code over a rewritten one: it brings
  back files the rewrite deleted, such as `pkg/policycore/go.mod`. Re-run
  `rewrite-imports.sh` on the clone instead.

## Decisions

| Decision | Choice | Status |
| --- | --- | --- |
| Module layout | Single module, `policycore` under `pkg/` | Chosen |
| Repo and module name | `github.com/rshade/tail-acl` | Confirmed 2026-11-02 |
| Tag scheme | Plain `vX.Y.Z` (no component prefix) | Follows layout |
| Version continuity | Continue from `0.3.0`; manifest starts there | Chosen, revisit at step 4 |
| Old `tail-acl/vX` tags | Stay in `tailscale-utils` as history | Proposed |
| Public API in `pkg/` | Everything stays under `pkg/policycore`, including `alpha` | Chosen 2026-10-28 |
| History scrub | `--replace-text`, `--replace-message`, `--mailmap` (see below) | Chosen 2026-10-28 |

Trade-offs accepted with a single module:

- One version number covers the CLI and the library.
- A `policycore` consumer's module graph includes `tail-acl`'s requirements
  (measured above: 6 modules for the library, 47 for the whole module).
- If `policycore` later needs an independent version, split it with a
  `pkg/policycore/go.mod`; the import path stays the same.

## Steps

### 0. Pre-flight

- [x] Measure the dependency footprint (see dry-run results).
- [x] Confirm the repo name: `rshade/tail-acl`, confirmed 2026-11-02. The
      `pkg/` public-API question is settled too: keep everything under `pkg/`.
- [x] Check whether `tailscale-utils` is already public. Private (checked 2026-10-28), as is the empty `rshade/tail-acl`.
- [x] Audit for sensitive data before anything goes public:
  - `integration/testdata/.tail-acl-state.json`
  - `pkg/policycore/testdata/`
  - real tailnet names, IPs, hostnames, tokens
  - Use the monorepo's `scripts/sanitize-policy.sh` where it applies.
- [x] Run `gitleaks` over the full history of the extracted repo.

### 1. Extract with history

`git filter-repo` refuses to run on anything but a fresh clone, so always use
a throwaway one. It needs installing; `uvx git-filter-repo` runs it without a
permanent install.

```bash
git clone git@github.com:rshade/tailscale-utils.git extract
cd extract
uvx git-filter-repo \
  --path tail-acl --path policycore \
  --path-rename tail-acl/: \
  --path-rename policycore/:pkg/policycore/
```

Then scrub the two real identifiers (see "History scrub" below). This repo is
public, so the plan keeps placeholders instead of the real values. Find them in
the monorepo: `<personal-email>` is the author address that is not a GitHub
noreply one (`git log --format=%ae | sort -u`), and `<lab-tailnet>` is the
`*.ts.net` name in the testdata provenance comments
(`grep -rhoE '[a-z0-9-]+\.ts\.net' tail-acl policycore`). Substitute them, then
write these two files outside the clone:

```text
# replace.txt
<personal-email>==>owner@example.com
<lab-tailnet>.ts.net==>example.ts.net
<lab-tailnet>==>example
```

```text
# mailmap.txt
Richard Shade <131337+rshade@users.noreply.github.com> <<personal-email>>
```

```bash
uvx git-filter-repo --force \
  --replace-text replace.txt --replace-message replace.txt \
  --mailmap mailmap.txt
git tag -d tail-ipam/v0.1.0 tailnet-audit/v0.1.0 tailnet-audit/v0.2.0 \
  tailnet-flow/v0.1.0 tailscale-doctor/v0.2.0
```

Confirm `git tag` lists only `tail-acl/v0.1.0` to `v0.3.0`, and that
`git log --all -p | grep -cE '<personal-email-local-part>|<lab-tailnet>'` prints `0`.

- [x] Dry run in a scratch clone (done; layout and size verified).
- [x] Re-run on a fresh clone immediately before the real move, so the history
      includes anything merged in the meantime. Done 2026-10-28 (re-run again
      right before publishing if the monorepo moves).
- [x] Delete the stray tags, keeping only `tail-acl/v0.1.0` to `v0.3.0`.
- [x] Verify `git log --follow` still tracks files across the rename.

### 2. Make it build

Run this from the root of the extracted clone, after the scrub. It is
idempotent, and it must be re-run after any `filter-repo` pass because history
rewrites discard working-tree edits:

```bash
#!/usr/bin/env bash
# rewrite-imports.sh
set -euo pipefail
rm -f pkg/policycore/go.mod pkg/policycore/go.sum
sed -i -e '1s#.*#module github.com/rshade/tail-acl#' \
  -e '/rshade\/tailscale-utils\/policycore/d' go.mod
grep -rlE 'github.com/rshade/tailscale-utils/(policycore|tail-acl)' . \
  --exclude-dir=.git | xargs sed -i -E \
  -e 's#github.com/rshade/tailscale-utils/policycore#github.com/rshade/tail-acl/pkg/policycore#g' \
  -e 's#github.com/rshade/tailscale-utils/tail-acl#github.com/rshade/tail-acl#g'
gofmt -s -w .
go mod tidy
```

Then delete `pkg/policycore/.github`, `.claude`, and `.agents` (byte-identical
to the root copies), and make these hand edits, which are not scripted:

- `NOTICE`: first line `tail-acl` instead of `tailscale-utils`.
- `README.md`: point the AX-conventions link at
  `docs/reference/ax-conventions.md`, and replace the `make build` sentence with
  `mise run build`.
- `docs/how-to/lint-policy.md`: link `gate-policy-changes-in-ci.md` locally.
- Copy `docs/how-to/gate-policy-changes-in-ci.md` (final link becomes
  `../README.md`) and `docs/reference/ax-conventions.md` from the monorepo, and
  list both in `docs/README.md`.
- `pkg/policycore/README.md`: rewrite the intro to say it is imported from
  `github.com/rshade/tail-acl/pkg/policycore/<pkg>`.

Steps, all done in the throwaway tree:

- [x] Delete `pkg/policycore/go.mod` and `go.sum`.
- [x] In the root `go.mod`: set `module github.com/rshade/tail-acl`, remove
      the `policycore` `require` and `replace`.
- [x] Rewrite imports with exact-path replacements only:
  - `github.com/rshade/tailscale-utils/policycore` →
    `github.com/rshade/tail-acl/pkg/policycore`
  - `github.com/rshade/tailscale-utils/tail-acl` →
    `github.com/rshade/tail-acl`
- [x] `go mod tidy && go build ./... && go vet ./... && go test ./...`
- [x] Fix `NOTICE` by hand.
- [x] Cross-compile for Windows, and `go vet -tags live_verify ./...` (compiles
      the tagged tests; running them still needs credentials). Done 2026-10-28.
- [x] Run the linters: `golangci-lint`, `markdownlint`, `actionlint`, `govulncheck`,
      `go-licenses` all pass on the assembled tree. Done 2026-10-28.

### 3. Repo scaffolding

Copy and trim from the monorepo:

- [x] `.github/workflows/ci.yml`, `release.yml`, `alpha-live-verify.yml`
      (path filter becomes `pkg/policycore/alpha/**`). Done; the live-verify
      job reads its tailnet credentials from secrets on the `live-verify`
      environment instead of Pulumi.
- [x] Merge `pkg/policycore/.github`, `.claude`, and `.agents` into the root
      copies where worth keeping, then delete the nested ones. They were
      byte-identical to the root copies; deleted.
- [x] `release-please-config.json` and manifest: one package, no component
      prefix, `include-component-in-tag: false`. Manifest starts at `0.3.0`.
- [x] `.goreleaser.yaml`: remove the tag-prefix workaround and the
      `GORELEASER_CURRENT_TAG` plumbing.
- [x] `mise.toml` (tool pins and tasks; there is no Makefile, everything runs
      as `mise run <task>`) and `commitlint.config.js`. Done 2026-10-28.
- [x] `renovate.json`.
- [x] Quality and security gates, borrowed from `ax-go` and `finfocus` and
      pinned in `mise.toml`. Run from the first commit. Done 2026-10-28 and
      verified locally against the extracted history: `trufflehog`,
      `gitleaks` (with `.gitleaks.toml`), `govulncheck`, `actionlint`,
      `markdownlint`, `commitlint`, `go-licenses`, plus CodeQL, `SECURITY.md`,
      and the `validate` checks; workflows are `ci.yml`, `secrets.yml`,
      `codeql.yml`, `apidiff.yml`, `release.yml`, and `alpha-live-verify.yml`.
      What each gate is:
  - `trufflehog` on PRs, pushes, and a weekly full-history schedule
    (neither sibling repo has it; pin 3.99.4 as `finfocus`'s `mise.toml`
    does), plus `.gitleaks.toml` for the one-off audit allowlist.
  - `govulncheck ./...` (both siblings).
  - The `ax-go` `validate` job: `go.mod` Go version matches `mise.toml`,
    `gofmt -s`, `go mod tidy` leaves no diff, `go vet`.
  - `actionlint`, `markdownlint`, and `commitlint` on PR commits.
  - CodeQL (`finfocus`'s `codeql.yml`), free on public repos.
  - `go-licenses check` against an allowlist (`finfocus`'s `license-check`).
  - `SECURITY.md` (`ax-go` has one to adapt).
- [x] `pkg/policycore` is public API, so also add an `apidiff` workflow
      (`scripts/apidiff.sh`, label-gated override; see the go-apidiff trap
      above). Defer the repo-specific
      Go checkers (`surfacecheck`, `doccover`, `deadcheck`, `slopcheck`); they
      live in `ax-go/internal/cmd` and would need porting. Skip `sizecheck`,
      `benchcheck`, and the `finfocus` agentic workflows.
- [x] Runners: GitHub-hosted (`ubuntu-latest`, as `finfocus` does) for now,
      not the `[self-hosted, linux, x64]` pool `ax-go` uses. Decided
      2026-10-28; temporary, until the GitHub-hosted minutes budget runs out.
  - Make the label a repository variable so the switch is a settings change:
    `runs-on: ${{ fromJSON(vars.RUNNER_LABELS || '["ubuntu-latest"]') }}`.
    Set `RUNNER_LABELS` to `["self-hosted","linux","x64"]` to switch.
  - Do not use the `ghcr.io/rshade/ci-ax-go` container image or `/opt/ci-cache`
    volumes in the shared workflows. Install tools with `mise install` so the
    same jobs run on either runner.
  - **Before switching to self-hosted, the repo must stay private or have
    "Require approval for all outside collaborators" set for fork PRs.** On a
    public repo, a fork PR otherwise runs arbitrary code on those machines.
- [x] `scripts/` and `lab/` pieces the tests or CI still need. None: all 17
      packages pass without them.
- [x] `LICENSE` and `NOTICE` (Apache 2.0). `tscli` is a library dependency,
      not incorporated source, so no extra attribution is needed.
- [x] Root `README.md`, `CLAUDE.md`, `AGENTS.md`; update docs that mention
      monorepo paths, including the `lint-policy.md` link. Done; the CI how-to
      and `ax-conventions.md` were copied into `docs/`.

### 4. Publish the new repo

Needs the user's explicit go-ahead; commits and the push are not to be run
speculatively.

- [x] Rebuild the extraction from step 1 and step 2 in a fresh clone, so it
      includes anything merged in the monorepo since 2026-10-28 (nothing had:
      monorepo HEAD `b247efc`, still 112 commits). Re-ran the whole `mise run`
      check set on the result; all pass. `release-check` needs an `origin`
      remote, because `filter-repo` strips it.
- [ ] Decide what to do with `CHANGELOG.md`: its links point at commits and
      issues in the private `tailscale-utils` repo and will 404 once the repo is
      public. Keep them or strip them.
- [x] Bring the verified result into this directory: fetched the extracted
      clone's `main` and tags and checked it out, instead of merging unrelated
      histories. The scaffolding and this plan are in the second commit on top.
- [ ] Run `mise trust` here once, then `mise install` (the user runs `mise
      trust`; it is a trust decision about the config).
- [ ] Push `main` to `rshade/tail-acl`, which already exists, is private, and
      was empty on 2026-10-28. Keep it private until the checks below pass,
      then make it public.
- [ ] Push `v0.3.0` at the same commit as `tail-acl/v0.3.0`. release-please
      needs it as its baseline with plain tags; without it, it tries to release
      the whole history.
- [ ] Repository settings before the first PR:
  - `RUNNER_LABELS` stays unset while on GitHub-hosted runners.
  - Branch protection requiring the CI checks (the `Protect main` ruleset).
  - Environment `live-verify` with required reviewers and a `main`-only
    branch policy. `alpha-live-verify.yml` runs repository code with tailnet
    credentials, so the job only runs from `main` and waits for that approval.
  - Environment secrets `TAILSCALE_API_KEY` and `TAILSCALE_TAILNET` on
    `live-verify` (never repository-level secrets), using a read-only API key
    or OAuth client.
  - Labels: `breaking-change-approved`.
  - Enable Renovate and private vulnerability reporting (`SECURITY.md` links
    to Security Advisories).
- [ ] Let release-please open its first PR; the next version is `v0.4.0` if the
      history since `0.3.0` includes a `feat:`.
- [ ] Confirm `go get github.com/rshade/tail-acl/pkg/policycore@<tag>` works
      from a scratch module.

### 5. Migrate the four sibling tools

For each of `tail-ipam`, `tailnet-audit`, `tailnet-flow`,
`tailscale-doctor`:

- [ ] Replace the `policycore` `require` and `replace` with a tagged
      `github.com/rshade/tail-acl` version.
- [ ] Rewrite the import paths with the same exact-path replacement as
      step 2.
- [ ] `go mod tidy`, `go build ./...`, `go test ./...`.
- [ ] Optional during transition: a local `go.work` pointing at the new repo
      checkout.

### 6. Clean up the monorepo

- [ ] Delete `tail-acl/` and `policycore/`.
- [ ] Remove them from `go.work`, `release-please-config.json`, and CI path
      filters (`alpha-live-verify.yml` is entirely about `policycore/alpha`).
- [ ] Fix or repoint docs that link into the removed directories.
- [ ] Update the `mise.toml` comment that refers to `tail-acl` as a sibling.
- [ ] Add a pointer to the new repo in the monorepo README.

## Order of operations

1. Pre-flight audit and a fresh extraction (steps 0 to 2).
2. Scaffold and publish the new repo (steps 3 and 4).
3. Migrate the sibling tools (step 5).
4. Remove the old directories (step 6).

Steps 4 and 5 must land before step 6, so the sibling tools never point at a
path that no longer exists.

## Risks

- **Sensitive data in history**: `filter-repo` keeps all history, so anything
  committed once becomes public. Mitigation: step 0 audit and `gitleaks`.
- **Hash tag rewrite**: a blanket `tailscale-utils` replacement would change
  sanitizer output. Mitigation: exact-path replacements only; the sanitizer
  tests would catch a regression.
- **Breaking API changes**: once `policycore` is consumed via tags, changes are
  no longer one atomic refactor across the repo. Pre-1.0 versioning and
  `alpha` marking mitigate this.
- **Dependency pollution**: `go-git`, `tscli`, and friends in the consumers'
  module graph. Mitigation: measured and accepted; split `policycore` into its
  own module if it hurts.
- **Release continuity**: the tag scheme changes. Mitigation: document it in
  the new repo's `CHANGELOG.md` and the monorepo README.

## Open questions

Settled: the repo and module name (`rshade/tail-acl`), and the public API
surface (everything stays under `pkg/policycore`, including `alpha`).

1. What to do with the `CHANGELOG.md` links to private commits and issues.
2. Whether to continue version numbers (`v0.4.0`) or restart at `v0.1.0`. The
   manifest currently starts at `0.3.0`, which continues them.
3. Whether the sibling tools should wait for the new repo's first tag or use a
   `go.work` during the transition.
4. Whether `ax-go`'s `apidiff` workflow is a silent no-op, given the go-apidiff
   bug under Go 1.27 (outside this plan; worth a separate check).
