#!/usr/bin/env bash
# Report incompatible changes to the public API under pkg/ since a base ref.
# Usage: scripts/apidiff.sh [base-ref]   (default: origin/main)
#
# Uses golang.org/x/exp/cmd/apidiff in export-file mode. go-apidiff is not used:
# v0.8.3 prints nothing and exits 0 under Go 1.27, so a gate built on it would
# pass every breaking change.
set -euo pipefail

base=${1:-origin/main}
apidiff_pkg=golang.org/x/exp/cmd/apidiff@v0.0.0-20261014143641-f0251eb4aa3e

root=$(git rev-parse --show-toplevel)
work=$(mktemp -d)
cleanup() {
  git -C "$root" worktree remove --force "$work/base" 2>/dev/null || true
  rm -rf "$work"
}
trap cleanup EXIT

GOBIN="$work/bin" go install "$apidiff_pkg"
git -C "$root" worktree add --detach --quiet "$work/base" "$base"

breaking=0
while read -r pkg; do
  export_file="$work/$(echo "$pkg" | tr / _).export"
  (cd "$work/base" && "$work/bin/apidiff" -w "$export_file" "$pkg")

  if ! (cd "$root" && go list "$pkg" >/dev/null 2>&1); then
    echo "## $pkg"
    echo "- package removed"
    breaking=1
    continue
  fi

  report=$(cd "$root" && "$work/bin/apidiff" -incompatible "$export_file" "$pkg")
  if [ -n "$report" ]; then
    echo "## $pkg"
    echo "$report"
    breaking=1
  fi
done < <(cd "$work/base" && go list ./pkg/...)

exit "$breaking"
