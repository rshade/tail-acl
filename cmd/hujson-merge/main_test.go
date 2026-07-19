package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tailscale/hujson"

	"github.com/rshade/tailscale-utils/tail-acl/internal/aclpolicy"
)

func mustParse(t *testing.T, s string) hujson.Value {
	t.Helper()
	v, err := hujson.Parse([]byte(s))
	if err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
	return v
}

// format normalizes a HuJSON string through the same Format() the tool applies,
// so structural comparisons don't depend on the input's whitespace.
func format(t *testing.T, s string) string {
	t.Helper()
	v := mustParse(t, s)
	v.Format()
	return string(v.Pack())
}

// mergeStrings parses base+add, merges, and returns the formatted result.
func mergeStrings(t *testing.T, base, add string) string {
	t.Helper()
	bv := mustParse(t, base)
	av := mustParse(t, add)
	if err := aclpolicy.MergeInto(&bv, &av); err != nil {
		t.Fatalf("aclpolicy.MergeInto: %v", err)
	}
	bv.Format()
	return string(bv.Pack())
}

func TestMergeInto(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		base, add string
		want      string
	}{
		{
			name: "adds a new object key",
			base: `{"a": 1}`,
			add:  `{"b": 2}`,
			want: `{"a": 1, "b": 2}`,
		},
		{
			name: "merges into an existing nested object",
			base: `{"tagOwners": {"tag:a": ["autogroup:admin"]}}`,
			add:  `{"tagOwners": {"tag:b": ["autogroup:admin"]}}`,
			want: `{"tagOwners": {"tag:a": ["autogroup:admin"], "tag:b": ["autogroup:admin"]}}`,
		},
		{
			name: "appends to an existing array (does not replace)",
			base: `{"grants": [{"src": ["a"]}]}`,
			add:  `{"grants": [{"src": ["b"]}]}`,
			want: `{"grants": [{"src": ["a"]}, {"src": ["b"]}]}`,
		},
		{
			name: "does not append a semantically identical array element",
			base: `{"grants": [{"src": ["a"], "dst": ["*"]}]}`,
			add:  `{"grants": [{"dst": ["*"], /* ignored */ "src": ["a"]}]}`,
			want: `{"grants": [{"src": ["a"], "dst": ["*"]}]}`,
		},
		{
			name: "does not append a grant with reordered selectors",
			base: `{"grants": [{"src": ["group:a", "group:b"], "dst": ["tag:x", "tag:y"], "ip": ["tcp:80", "tcp:443"]}]}`,
			add:  `{"grants": [{"ip": ["tcp:443", "tcp:80"], "dst": ["tag:y", "tag:x"], "src": ["group:b", "group:a"]}]}`,
			want: `{"grants": [{"src": ["group:a", "group:b"], "dst": ["tag:x", "tag:y"], "ip": ["tcp:80", "tcp:443"]}]}`,
		},
		{
			name: "does not append an SSH rule with reordered selectors",
			base: `{"ssh": [{"action": "accept", "src": ["group:a", "group:b"], "dst": ["tag:x", "tag:y"], "users": ["root", "autogroup:nonroot"]}]}`,
			add:  `{"ssh": [{"users": ["autogroup:nonroot", "root"], "dst": ["tag:y", "tag:x"], "src": ["group:b", "group:a"], "action": "accept"}]}`,
			want: `{"ssh": [{"action": "accept", "src": ["group:a", "group:b"], "dst": ["tag:x", "tag:y"], "users": ["root", "autogroup:nonroot"]}]}`,
		},
		{
			name: "overwrites a scalar",
			base: `{"a": 1}`,
			add:  `{"a": 2}`,
			want: `{"a": 2}`,
		},
		{
			name: "overwrites on a type mismatch (object -> scalar)",
			base: `{"a": {"x": 1}}`,
			add:  `{"a": 5}`,
			want: `{"a": 5}`,
		},
		{
			name: "adds a key absent from base",
			base: `{"acls": []}`,
			add:  `{"grants": [{"src": ["x"]}]}`,
			want: `{"acls": [], "grants": [{"src": ["x"]}]}`,
		},
		{
			// The real use: a peer-relay snippet contributes a tagOwners entry
			// (map merge) and a grant (array append) into the base policy.
			name: "acl snippet: tagOwners merge + grants append",
			base: `{"grants": [{"src": ["*"], "dst": ["*"]}], "tagOwners": {"tag:client": ["autogroup:admin"]}}`,
			add:  `{"grants": [{"src": ["autogroup:member"], "dst": ["tag:relay-server"]}], "tagOwners": {"tag:relay-server": ["autogroup:admin"]}}`,
			want: `{"grants": [{"src": ["*"], "dst": ["*"]}, {"src": ["autogroup:member"], "dst": ["tag:relay-server"]}], "tagOwners": {"tag:client": ["autogroup:admin"], "tag:relay-server": ["autogroup:admin"]}}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := mergeStrings(t, tt.base, tt.add)
			want := format(t, tt.want)
			if got != want {
				t.Errorf("merge mismatch\n got: %s\nwant: %s", got, want)
			}
		})
	}
}

func TestRepositoryRelayMergeIsIdempotent(t *testing.T) {
	t.Parallel()
	basePath := filepath.Join("testdata", "acl.hujson")
	addPath := filepath.Join("testdata", "peer-relay.acl.hujson")

	first, err := aclpolicy.MergePair(basePath, addPath)
	if err != nil {
		t.Fatal(err)
	}
	tempBase := filepath.Join(t.TempDir(), "acl.hujson")
	writeTestFile(t, tempBase, string(first))
	second, err := aclpolicy.MergePair(tempBase, addPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Error("merging the relay snippet a second time changed the policy")
	}
}

func TestMergePreservesComments(t *testing.T) {
	t.Parallel()
	base := `{
		// keep this comment
		"tagOwners": {"tag:a": ["autogroup:admin"]},
	}`
	add := `{"tagOwners": {"tag:b": ["autogroup:admin"]}}`
	got := mergeStrings(t, base, add)

	if !strings.Contains(got, "// keep this comment") {
		t.Errorf("base comment was dropped:\n%s", got)
	}
	if !strings.Contains(got, "tag:b") {
		t.Errorf("added key missing from result:\n%s", got)
	}
}

func TestDirectoryModeMergesACLFilesInOrder(t *testing.T) {
	t.Parallel()
	dir1 := t.TempDir()
	dir2 := t.TempDir()
	writeTestFile(t, filepath.Join(dir1, "10-base.acl.hujson"), `{
		// comments are accepted as input
		"grants": [{"src": ["base"], "dst": ["*"]}],
		"tagOwners": {"tag:base": ["autogroup:admin"]},
		"version": 1,
	}`)
	writeTestFile(t, filepath.Join(dir1, "20.acl.json"), `{
		"grants": [{"src": ["second"], "dst": ["*"]}],
		"version": 2
	}`)
	writeTestFile(t, filepath.Join(dir1, "package.json"), `{"mustNotAppear": true}`)
	writeTestFile(t, filepath.Join(dir2, "extra.acl.hujson"), `{
		"tagOwners": {"tag:extra": ["autogroup:admin"]},
		"version": 3,
	}`)

	var stdout, stderr bytes.Buffer
	if err := run([]string{"--dir", dir1, "--out", "-", "--dir", dir2}, &stdout, &stderr); err != nil {
		t.Fatalf("run directory mode: %v", err)
	}
	if !json.Valid(stdout.Bytes()) {
		t.Fatalf("directory output is not standard JSON:\n%s", stdout.String())
	}

	var got map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal output: %v", err)
	}
	if got["version"] != float64(3) {
		t.Errorf("version = %#v, want 3 (last directory wins)", got["version"])
	}
	if _, ok := got["mustNotAppear"]; ok {
		t.Error("generic package.json was merged")
	}
	grants, ok := got["grants"].([]any)
	if !ok || len(grants) != 2 {
		t.Errorf("grants = %#v, want two appended grants", got["grants"])
	}
	tagOwners, ok := got["tagOwners"].(map[string]any)
	if !ok || len(tagOwners) != 2 {
		t.Errorf("tagOwners = %#v, want two merged owners", got["tagOwners"])
	}
	if strings.Contains(stdout.String(), "comments are accepted") {
		t.Error("directory output retained a HuJSON comment instead of producing standard JSON")
	}
}

func TestDirectoryModeExcludesOutputOnRerun(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	writeTestFile(t, filepath.Join(dir, "base.acl.hujson"), `{"grants": [{"src": ["base"]}]}`)
	out := filepath.Join(dir, "acl.json")

	for i := range 2 {
		if err := mergeDirectories([]string{dir}, out, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
			t.Fatalf("mergeDirectories run %d: %v", i+1, err)
		}
	}
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Grants []any `json:"grants"`
	}
	if err = json.Unmarshal(b, &got); err != nil {
		t.Fatalf("unmarshal output: %v", err)
	}
	if len(got.Grants) != 1 {
		t.Errorf("rerun duplicated generated acl.json: got %d grants, want 1", len(got.Grants))
	}
}

func TestDirectoryModeDeduplicatesDirectories(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	writeTestFile(t, filepath.Join(dir, "acl.hujson"), `{"grants": [{"src": ["once"]}]}`)

	paths, err := aclpolicy.ACLFilesInDirectories([]string{dir, dir}, "-")
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 1 {
		t.Fatalf("got %d paths, want one deduplicated input: %v", len(paths), paths)
	}
}

func TestIsACLFilename(t *testing.T) {
	t.Parallel()
	tests := map[string]bool{
		"acl.json":              true,
		"ACL.HUJSON":            true,
		"network.acl.json":      true,
		"peer-relay.acl.hujson": true,
		"oracle.json":           false,
		"miracle.json":          false,
		"policy.json":           false,
		"base.hujson":           false,
		".hujson":               false,
		"package.json":          false,
		"notes.txt":             false,
	}
	for name, want := range tests {
		if got := aclpolicy.IsACLFilename(name); got != want {
			t.Errorf("isACLFilename(%q) = %v, want %v", name, got, want)
		}
	}
}

func writeTestFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
