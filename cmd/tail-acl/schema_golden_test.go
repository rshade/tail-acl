package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

// updateSchemaGolden regenerates testdata/schema.golden.json. Run
// `go test . -update` and read the diff: -update blesses a wrong document as
// happily as a right one.
//
//nolint:gochecknoglobals // a test flag must be package-level to register with the flag package
var updateSchemaGolden = flag.Bool("update", false, "update the schema golden file")

// TestSchemaSurvivesCobraConversion locks the machine-readable contract that
// agents and example-lab consume. The golden is captured from the stdlib
// flag implementation; the cobra implementation must reproduce it exactly, save
// for the help flag cobra injects into every command.
func TestSchemaSurvivesCobraConversion(t *testing.T) {
	t.Parallel()

	var stdout, stderr bytes.Buffer
	err := run(
		context.Background(),
		[]string{"-schema"},
		func(string) string { return "" },
		&http.Client{},
		"https://api.example.com",
		&stdout,
		&stderr,
	)
	if err != nil {
		t.Fatalf("-schema returned %v (stderr: %s)", err, stderr.String())
	}
	got := schemaWithoutHelp(t, stdout.Bytes(), "flags")

	path := filepath.Join("testdata", "schema.golden.json")
	if *updateSchemaGolden {
		if writeErr := os.WriteFile(path, got, 0o600); writeErr != nil {
			t.Fatalf("update golden: %v", writeErr)
		}
		t.Logf("updated %s", path)
		return
	}
	want, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatalf("read golden: %v", readErr)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("schema document changed\n got: %s\nwant: %s", got, want)
	}
}

// schemaWithoutHelp re-encodes a schema document with its flag array stripped
// of cobra's injected help entry and its keys sorted, so one golden compares
// equal across the stdlib flag and cobra implementations.
func schemaWithoutHelp(t *testing.T, raw []byte, flagField string) []byte {
	t.Helper()

	var document map[string]any
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatalf("decode schema: %v", err)
	}
	entries, ok := document[flagField].([]any)
	if !ok {
		t.Fatalf("schema field %q is not an array", flagField)
	}
	kept := make([]any, 0, len(entries))
	for _, entry := range entries {
		if item, isObject := entry.(map[string]any); isObject && item["name"] == "help" {
			continue
		}
		kept = append(kept, entry)
	}
	document[flagField] = kept

	normalized, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		t.Fatalf("encode schema: %v", err)
	}
	return append(normalized, '\n')
}
