package aclpolicy_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rshade/tail-acl/internal/aclpolicy"
)

func TestLoadLintConfigAcceptsHuJSONComments(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "lint.hujson")
	if err := os.WriteFile(path, []byte(`{
		"checks": {
			"broad-rule-untested": {
				// This destination is intentionally open.
				"allowBroad": ["tag:printer"],
			},
		},
	}`), 0o644); err != nil {
		t.Fatal(err)
	}
	config, err := aclpolicy.LoadLintConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := config.Checks.BroadRuleUntested.AllowBroad; len(got) != 1 || got[0] != "tag:printer" {
		t.Errorf("allowBroad = %#v", got)
	}
}

func TestLoadLintConfigRejectsUnknownField(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "lint.hujson")
	raw := []byte(`{"checks":{"broad-rule-untested":{"allowBrood":["tag:db"]}}}`)
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := aclpolicy.LoadLintConfig(path); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("error = %v, want unknown field", err)
	}
}

func TestLoadLintConfigRejectsTrailingValue(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "lint.hujson")
	if err := os.WriteFile(path, []byte(`{} {}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := aclpolicy.LoadLintConfig(path); err == nil {
		t.Fatal("LoadLintConfig accepted a trailing JSON value")
	}
}
