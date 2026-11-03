package aclpolicy_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/rshade/tsacl/internal/aclpolicy"
)

func TestNormalizeProducesStandardJSON(t *testing.T) {
	t.Parallel()
	path := filepath.Join("testdata", "normalize.hujson")

	got, err := aclpolicy.Normalize(path)
	if err != nil {
		t.Fatal(err)
	}
	if !json.Valid(got) {
		t.Fatalf("Normalize returned invalid JSON: %s", got)
	}

	// This golden deliberately bypasses the package's assertGolden helper.
	// assertGolden re-encodes through json.MarshalIndent, which would reformat
	// exactly the byte layout Normalize exists to preserve — comments blanked to
	// spaces, every offset still aligned with the HuJSON source.
	goldenPath := filepath.Join("testdata", "normalize.golden.json")
	if *updateGolden {
		if writeErr := os.WriteFile(goldenPath, got, 0o644); writeErr != nil {
			t.Fatal(writeErr)
		}
		t.Logf("updated %s", goldenPath)
		return
	}
	want, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("normalized bytes differ\n got: %q\nwant: %q", got, want)
	}
}

func TestNormalizeIsSemanticallyEqualToTypedLoad(t *testing.T) {
	t.Parallel()
	path := filepath.Join("testdata", "normalize.hujson")

	normalized, err := aclpolicy.Normalize(path)
	if err != nil {
		t.Fatal(err)
	}
	var got any
	if unmarshalErr := json.Unmarshal(normalized, &got); unmarshalErr != nil {
		t.Fatal(unmarshalErr)
	}

	policy, err := aclpolicy.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	var want any
	if unmarshalErr := json.Unmarshal(encoded, &want); unmarshalErr != nil {
		t.Fatal(unmarshalErr)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("normalized document = %#v, typed policy = %#v", got, want)
	}
}

func TestNormalizeRejectsInvalidHuJSON(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "invalid.hujson")
	writeFile(t, path, `{"grants": [`)

	if _, err := aclpolicy.Normalize(path); err == nil {
		t.Fatal("Normalize accepted invalid HuJSON")
	}
}

// TestNormalizeRejectsDuplicateMembers locks normalize to the same refusal Load
// makes. hujson keeps both members, so standardizing would emit a document whose
// strict-JSON consumers resolve last-wins while tsacl resolves first-wins —
// handing an operator the member the tool itself discards.
func TestNormalizeRejectsDuplicateMembers(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "duplicate.hujson")
	writeFile(t, path, `{"hosts": {"web": "100.64.0.10"}, "hosts": {"web": "100.64.0.11"}}`)

	_, err := aclpolicy.Normalize(path)
	if err == nil {
		t.Fatal("Normalize accepted duplicate object members")
	}
	if !strings.Contains(err.Error(), `duplicate object member "hosts"`) {
		t.Errorf("error = %v, want a duplicate-member diagnostic", err)
	}
}
