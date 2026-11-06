package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMergePairKeepsCommentsFromBothInputs(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	base := filepath.Join(dir, "base.hujson")
	add := filepath.Join(dir, "add.hujson")
	writeTestPolicy(t, base, "{\n\t// base note\n\t\"tagOwners\": {\"tag:a\": [\"autogroup:admin\"]},\n}\n")
	writeTestPolicy(t, add, "{\n\t\"tagOwners\": {\"tag:b\": [\"autogroup:admin\"]},\n"+
		"\t// add note\n\t\"hosts\": {\"b\": \"100.64.0.2\"},\n}\n")

	stdout, err := runTSACL(t, base, "merge", "--base", base, "--add", add)
	if err != nil {
		t.Fatal(err)
	}
	if status := decodeStatus(t, stdout); status != statusOK {
		t.Errorf("status = %q, want %q", status, statusOK)
	}
	got := readPolicy(t, base)
	for _, want := range []string{"// base note", "// add note", "tag:a", "tag:b"} {
		if !strings.Contains(got, want) {
			t.Errorf("merged policy missing %q:\n%s", want, got)
		}
	}
}

func TestMergePairOutLeavesBaseUntouched(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	base := filepath.Join(dir, "base.hujson")
	add := filepath.Join(dir, "add.hujson")
	out := filepath.Join(dir, "out.hujson")
	const baseText = "{\n\t\"hosts\": {\"a\": \"100.64.0.1\"},\n}\n"
	writeTestPolicy(t, base, baseText)
	writeTestPolicy(t, add, "{\n\t\"hosts\": {\"b\": \"100.64.0.2\"},\n}\n")

	if _, err := runTSACL(t, out, "merge", "--base", base, "--add", add, "--out", out); err != nil {
		t.Fatal(err)
	}
	if got := readPolicy(t, base); got != baseText {
		t.Errorf("--out rewrote the base:\n%s", got)
	}
	if got := readPolicy(t, out); !strings.Contains(got, `"b"`) {
		t.Errorf("--out missing the merged host:\n%s", got)
	}
}

func TestMergeDirOutOverridesFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	writeTestPolicy(t, filepath.Join(dir, "base.acl.hujson"), "{\n\t\"hosts\": {\"a\": \"100.64.0.1\"},\n}\n")
	out := filepath.Join(dir, "compiled.json")
	if _, err := runTSACL(t, filepath.Join(dir, "unused.json"), "merge", "--dir", dir, "--out", out); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "unused.json")); err == nil {
		t.Error("--out was ignored: --file was written")
	}
	if got := readPolicy(t, out); !strings.Contains(got, `"a"`) {
		t.Errorf("compiled output missing host:\n%s", got)
	}
}

func TestMergeRejectsBadFlagCombinations(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	policy := filepath.Join(dir, "acl.hujson")
	writeTestPolicy(t, policy, "{}\n")
	for name, args := range map[string][]string{
		"nothing":         {"merge"},
		"base alone":      {"merge", "--base", policy},
		"add alone":       {"merge", "--add", policy},
		"dir with pair":   {"merge", "--dir", dir, "--base", policy, "--add", policy},
		"unreadable base": {"merge", "--base", filepath.Join(dir, "missing.hujson"), "--add", policy},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := runTSACL(t, policy, args...); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

func TestMergeDirErrorNamesTheFilenameRule(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	writeTestPolicy(t, filepath.Join(dir, "policy.json"), "{}\n")
	_, err := runTSACL(t, filepath.Join(dir, "out.json"), "merge", "--dir", dir)
	if err == nil || !strings.Contains(err.Error(), "*.acl.hujson") {
		t.Fatalf("error = %v, want it to state the acl.* naming rule", err)
	}
}
