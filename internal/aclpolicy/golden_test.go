package aclpolicy_test

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"
)

// updateGolden regenerates the golden files instead of asserting against them.
// Run `go test ./internal/aclpolicy -update`, then read the resulting diff:
// -update will bless a wrong verdict exactly as readily as a right one.
//
//nolint:gochecknoglobals // a test flag must be package-level to register with the flag package
var updateGolden = flag.Bool("update", false, "rewrite golden files from current output")

// assertGolden compares value's indented JSON encoding against the named golden
// file byte for byte. Every golden in this package goes through it so the
// encoding and the regeneration path stay identical across tests.
func assertGolden(t *testing.T, name string, value any) {
	t.Helper()
	got, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')

	path := filepath.Join("testdata", name)
	if *updateGolden {
		if err = os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("updated %s", path)
		return
	}

	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("%s:\ngot:\n%s\nwant:\n%s", name, got, want)
	}
}
