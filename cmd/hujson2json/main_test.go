package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// policyWithComments exercises every HuJSON feature that breaks a standard JSON
// parser: line comments, a block comment, and trailing commas in both an object
// and an array.
const policyWithComments = `{
	// Named routes, hoisted.
	"routes": {
		"prod-db": ["10.1.0.0/24"], /* inline */
	},
	"tagOwners": {
		"tag:router": ["autogroup:admin"],
	},
}
`

func TestConvertsHuJSONFromStdin(t *testing.T) {
	t.Parallel()

	var stdout, stderr bytes.Buffer
	if err := run(nil, strings.NewReader(policyWithComments), &stdout, &stderr); err != nil {
		t.Fatalf("run: %v", err)
	}
	if stderr.Len() != 0 {
		t.Errorf("stderr = %q; want empty", stderr.String())
	}

	var got map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, stdout.String())
	}
	if _, ok := got["routes"]; !ok {
		t.Errorf("output missing routes key: %v", got)
	}
}

func TestConvertsHuJSONFromFile(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "acl.hujson")
	if err := os.WriteFile(path, []byte(policyWithComments), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	var stdout, stderr bytes.Buffer
	if err := run([]string{"--file", path}, nil, &stdout, &stderr); err != nil {
		t.Fatalf("run: %v", err)
	}
	if !json.Valid(stdout.Bytes()) {
		t.Errorf("output is not valid JSON: %s", stdout.String())
	}
}

// Object member order is the reason standardize reflows with [json.Indent] rather
// than decoding and re-encoding: a map round-trip would sort the keys, which
// silently changes what a positional jq query returns.
func TestPreservesMemberOrder(t *testing.T) {
	t.Parallel()

	var stdout, stderr bytes.Buffer
	if err := run(nil, strings.NewReader(policyWithComments), &stdout, &stderr); err != nil {
		t.Fatalf("run: %v", err)
	}
	routes := strings.Index(stdout.String(), `"routes"`)
	tagOwners := strings.Index(stdout.String(), `"tagOwners"`)
	if routes == -1 || tagOwners == -1 {
		t.Fatalf("both keys must appear: %s", stdout.String())
	}
	if routes > tagOwners {
		t.Errorf("routes must precede tagOwners as authored; got:\n%s", stdout.String())
	}
}

func TestCompactEmitsSingleLine(t *testing.T) {
	t.Parallel()

	var stdout, stderr bytes.Buffer
	if err := run([]string{"--compact"}, strings.NewReader(policyWithComments), &stdout, &stderr); err != nil {
		t.Fatalf("run: %v", err)
	}
	if lines := strings.Count(strings.TrimSuffix(stdout.String(), "\n"), "\n"); lines != 0 {
		t.Errorf("compact output spans %d extra lines:\n%s", lines, stdout.String())
	}
	if !json.Valid(stdout.Bytes()) {
		t.Errorf("compact output is not valid JSON: %s", stdout.String())
	}
}

// A diagnostic that leaks onto stdout corrupts the pipe this tool exists to
// feed, so the failure path must leave stdout untouched.
func TestInvalidHuJSONFailsWithCleanStdout(t *testing.T) {
	t.Parallel()

	var stdout, stderr bytes.Buffer
	err := run(nil, strings.NewReader(`{"unterminated": `), &stdout, &stderr)
	if err == nil {
		t.Fatal("run error = nil; want a standardize failure")
	}
	if !strings.Contains(err.Error(), "standardizing stdin") {
		t.Errorf("error = %v; want it to name the source", err)
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout = %q; want empty on failure", stdout.String())
	}
}

func TestSchemaIsValidJSON(t *testing.T) {
	t.Parallel()

	var stdout, stderr bytes.Buffer
	if err := run([]string{"--schema"}, nil, &stdout, &stderr); err != nil {
		t.Fatalf("run: %v", err)
	}
	var doc struct {
		Name  string `json:"name"`
		Flags []struct {
			Name string `json:"name"`
		} `json:"flags"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &doc); err != nil {
		t.Fatalf("schema is not valid JSON: %v", err)
	}
	if doc.Name != "hujson2json" {
		t.Errorf("schema name = %q; want hujson2json", doc.Name)
	}
	if len(doc.Flags) == 0 {
		t.Error("schema lists no flags")
	}
}

func TestRejectsPositionalArguments(t *testing.T) {
	t.Parallel()

	var stdout, stderr bytes.Buffer
	err := run([]string{"acl.hujson"}, strings.NewReader(policyWithComments), &stdout, &stderr)
	if err == nil {
		t.Fatal("run error = nil; want a positional-argument rejection")
	}
	if !strings.Contains(err.Error(), "--file") {
		t.Errorf("error = %v; want it to point at --file", err)
	}
}
