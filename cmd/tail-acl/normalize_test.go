package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rshade/tailscale-utils/tail-acl/internal/aclpolicy"
)

func TestNormalizeCommandEmitsBareStandardJSON(t *testing.T) {
	t.Parallel()
	path := filepath.Join("..", "..", "internal", "aclpolicy", "testdata", "normalize.hujson")
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	err = run(
		context.Background(),
		[]string{"--file", path, cmdNormalize},
		func(string) string { return "" },
		&http.Client{},
		"https://api.example.com",
		&stdout,
		&stderr,
	)
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	if stderr.Len() != 0 {
		t.Errorf("stderr = %q, want empty", stderr.String())
	}
	// Compare against the library, not aclpolicy's golden file: that golden is
	// rewritten by the aclpolicy package's own -update run, which go test may
	// execute concurrently with this package. What this test uniquely locks is
	// that the CLI emits the library's bytes verbatim — no envelope, no banner,
	// and no trailing summary line.
	want, err := aclpolicy.Normalize(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(stdout.Bytes(), want) {
		t.Errorf("stdout differs\n got: %q\nwant: %q", stdout.Bytes(), want)
	}
	if !json.Valid(stdout.Bytes()) {
		t.Fatalf("stdout is not standard JSON: %s", stdout.Bytes())
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, original) {
		t.Error("normalize modified the policy file")
	}
}

func TestNormalizeCommandJSONFormatUsesEnvelope(t *testing.T) {
	t.Parallel()
	path := filepath.Join("..", "..", "internal", "aclpolicy", "testdata", "normalize.hujson")
	var stdout, stderr bytes.Buffer
	err := run(
		context.Background(),
		[]string{"--format", formatJSON, "--file", path, cmdNormalize},
		func(string) string { return "" },
		&http.Client{},
		"https://api.example.com",
		&stdout,
		&stderr,
	)
	if err != nil {
		t.Fatalf("normalize -format json: %v", err)
	}
	var envelope struct {
		SchemaVersion string          `json:"schema_version"`
		Command       string          `json:"command"`
		Status        string          `json:"status"`
		Policy        json.RawMessage `json:"policy"`
	}
	if unmarshalErr := json.Unmarshal(stdout.Bytes(), &envelope); unmarshalErr != nil {
		t.Fatal(unmarshalErr)
	}
	if envelope.SchemaVersion != schemaVersion || envelope.Command != cmdNormalize || envelope.Status != statusOK {
		t.Errorf("envelope metadata = %#v", envelope)
	}
	if !json.Valid(envelope.Policy) {
		t.Fatalf("envelope policy is not JSON: %s", envelope.Policy)
	}
	if bytes.Equal(stdout.Bytes(), envelope.Policy) {
		t.Error("JSON format emitted the bare policy instead of an envelope")
	}
	if stderr.Len() != 0 {
		t.Errorf("stderr = %q, want empty", stderr.String())
	}
}

func TestNormalizeCommandInvalidInputIsExitTwoAndWritesNoStdout(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "invalid.hujson")
	if err := os.WriteFile(path, []byte(`{"grants": [`), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	err := run(
		context.Background(),
		[]string{"--file", path, cmdNormalize},
		func(string) string { return "" },
		&http.Client{},
		"https://api.example.com",
		&stdout,
		&stderr,
	)
	if err == nil {
		t.Fatal("normalize accepted invalid HuJSON")
	}
	if code := exitCode(err); code != exitUsage {
		t.Fatalf("exit code = %d, want %d (%v)", code, exitUsage, err)
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout = %q, want empty", stdout.String())
	}
	if !strings.Contains(err.Error(), "invalid.hujson") {
		t.Errorf("error = %v, want source path", err)
	}
}
