package observedstate_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rshade/tail-acl/internal/aclpolicy"
	"github.com/rshade/tail-acl/internal/observedstate"
)

func TestRecordKeepsTailnetsIndependent(t *testing.T) {
	t.Parallel()
	if aclpolicy.IsACLFilename(observedstate.FileName) {
		t.Fatalf("state file %q is eligible as a directory-merge policy input", observedstate.FileName)
	}
	policyPath := filepath.Join(t.TempDir(), "acl.hujson")
	if err := observedstate.Record(policyPath, "one.example", `"etag-one"`); err != nil {
		t.Fatal(err)
	}
	if err := observedstate.Record(policyPath, "two.example", `"etag-two"`); err != nil {
		t.Fatal(err)
	}

	for tailnet, want := range map[string]string{
		"one.example": `"etag-one"`,
		"two.example": `"etag-two"`,
	} {
		got, err := observedstate.Read(policyPath, tailnet)
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Errorf("Read(%q) = %q, want %q", tailnet, got, want)
		}
	}

	info, err := os.Stat(observedstate.Path(policyPath))
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("state mode = %04o, want 0600", got)
	}
}

func TestReadFailsClosedForMissingUnreadableAndUnkeyedState(t *testing.T) {
	t.Parallel()
	tempDir := t.TempDir()
	policyPath := filepath.Join(tempDir, "acl.hujson")

	_, err := observedstate.Read(policyPath, "example.com")
	if err == nil || !strings.Contains(err.Error(), "no such file") {
		t.Fatalf("missing state error = %v", err)
	}
	err = os.WriteFile(observedstate.Path(policyPath), []byte("not JSON\n"), 0o600)
	if err != nil {
		t.Fatal(err)
	}
	_, err = observedstate.Read(policyPath, "example.com")
	if err == nil || !strings.Contains(err.Error(), "decoding JSON") {
		t.Fatalf("unreadable state error = %v", err)
	}
	const emptyState = "{\n  \"schema_version\": \"1\",\n  \"etags\": {}\n}\n"
	err = os.WriteFile(observedstate.Path(policyPath), []byte(emptyState), 0o600)
	if err != nil {
		t.Fatal(err)
	}
	_, err = observedstate.Read(policyPath, "example.com")
	if err == nil || !strings.Contains(err.Error(), "no ETag") {
		t.Fatalf("unkeyed state error = %v", err)
	}
}

func TestRecordRefusesToReplaceCorruptState(t *testing.T) {
	t.Parallel()
	policyPath := filepath.Join(t.TempDir(), "acl.hujson")
	statePath := observedstate.Path(policyPath)
	const corrupt = "do not replace me\n"
	if err := os.WriteFile(statePath, []byte(corrupt), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := observedstate.Record(policyPath, "example.com", `"etag"`); err == nil {
		t.Fatal("Record succeeded with corrupt existing state")
	}
	got, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != corrupt {
		t.Errorf("corrupt state was replaced: %q", got)
	}
}
