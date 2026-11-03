package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

const jqPolicyFixture = "jq_policy.hujson"

// runJQCommand drives the whole CLI so every assertion covers the real
// dispatch, format resolution, and exit-code mapping rather than runJQ alone.
func runJQCommand(t *testing.T, format, program string) (bytes.Buffer, bytes.Buffer, error) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	err := run(context.Background(), []string{
		"--file", filepath.Join("testdata", jqPolicyFixture), "--format", format, cmdJQ, program,
	}, func(string) string { return "" }, &http.Client{}, "https://api.example.com", &stdout, &stderr)
	return stdout, stderr, err
}

// TestJQHumanFormatStreamsNDJSON locks the composable half of the contract:
// human output is one bare JSON value per line, with no summary line to strip.
func TestJQHumanFormatStreamsNDJSON(t *testing.T) {
	t.Parallel()

	want, err := os.ReadFile(filepath.Join("testdata", "jq_results.golden.ndjson"))
	if err != nil {
		t.Fatal(err)
	}
	stdout, stderr, runErr := runJQCommand(t, formatHuman, ".grants[].src[]")
	if runErr != nil {
		t.Fatalf("jq returned %v (stderr: %s)", runErr, stderr.String())
	}
	if !bytes.Equal(stdout.Bytes(), want) {
		t.Fatalf("stdout = %q, want %q", stdout.Bytes(), want)
	}
}

// TestJQJSONFormatWrapsResultsInEnvelope locks the machine contract. The
// envelope's file field carries an OS-dependent separator, so this asserts the
// versioned keys a consumer actually branches on rather than golden bytes.
func TestJQJSONFormatWrapsResultsInEnvelope(t *testing.T) {
	t.Parallel()

	stdout, stderr, runErr := runJQCommand(t, formatJSON, ".grants[].src[]")
	if runErr != nil {
		t.Fatalf("jq returned %v (stderr: %s)", runErr, stderr.String())
	}
	var got struct {
		SchemaVersion string `json:"schema_version"`
		Tool          string `json:"tool"`
		Command       string `json:"command"`
		Status        string `json:"status"`
		Results       []any  `json:"results"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatalf("envelope did not decode: %v (stdout: %s)", err, stdout.String())
	}
	if got.SchemaVersion != schemaVersion || got.Tool != toolName ||
		got.Command != cmdJQ || got.Status != statusOK {
		t.Errorf("envelope = %+v, want schema %s tool %s command %s status %s",
			got, schemaVersion, toolName, cmdJQ, statusOK)
	}
	want := []any{"group:dev", "tag:ci"}
	if len(got.Results) != len(want) {
		t.Fatalf("results = %v, want %v", got.Results, want)
	}
	for i := range want {
		if got.Results[i] != want[i] {
			t.Errorf("results[%d] = %v, want %v", i, got.Results[i], want[i])
		}
	}
}

// TestJQEmptyResultSetIsSuccessWithEmptyResults pins the exit-code decision
// issue #169 called out: a query matching nothing is success, not jq's own
// `-e` convention, and the envelope still carries the results key.
func TestJQEmptyResultSetIsSuccessWithEmptyResults(t *testing.T) {
	t.Parallel()

	stdout, stderr, runErr := runJQCommand(t, formatJSON, ".grants[] | select(false)")
	if runErr != nil {
		t.Fatalf("jq returned %v (stderr: %s)", runErr, stderr.String())
	}
	if !bytes.Contains(stdout.Bytes(), []byte(`"results": []`)) {
		t.Errorf("stdout = %s, want an empty results array", stdout.String())
	}
}

// TestJQPreservesLargeIntegerPrecision guards the UseNumber decode in
// decodePolicyForQuery. Without it the fixture's routeID decodes through a
// float64 and comes back ...992, silently corrupting a policy value.
func TestJQPreservesLargeIntegerPrecision(t *testing.T) {
	t.Parallel()

	const want = "9007199254740993"
	stdout, stderr, runErr := runJQCommand(t, formatHuman,
		`.nodeAttrs[0].app["tailscale.com/app-connectors"][0].routeID`)
	if runErr != nil {
		t.Fatalf("jq returned %v (stderr: %s)", runErr, stderr.String())
	}
	if got := string(bytes.TrimSpace(stdout.Bytes())); got != want {
		t.Errorf("routeID = %s, want %s", got, want)
	}
}

func TestJQMalformedProgramIsUsageErrorWithEmptyStdout(t *testing.T) {
	t.Parallel()

	var stdout, stderr bytes.Buffer
	err := run(context.Background(), []string{cmdJQ, ".grants["}, func(string) string { return "" },
		&http.Client{}, "https://api.example.com", &stdout, &stderr)
	if exitCode(err) != exitUsage {
		t.Fatalf("exitCode(%v) = %d, want %d", err, exitCode(err), exitUsage)
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
	if err == nil {
		t.Fatal("want a parse error for the caller to print to stderr")
	}
}

// TestJQEvaluationErrorIsUsageError covers the failure gojq raises mid-run
// rather than at parse time. JSON output buffers, so its stdout stays empty;
// human output has already streamed the values produced before the error, and
// the non-zero exit is what marks the stream truncated.
func TestJQEvaluationErrorIsUsageError(t *testing.T) {
	t.Parallel()

	for _, testCase := range []struct {
		format     string
		wantStdout string
	}{
		{formatJSON, ""},
		{formatHuman, "\"group:dev\"\n\"tag:ci\"\n"},
	} {
		t.Run(testCase.format, func(t *testing.T) {
			t.Parallel()
			stdout, _, err := runJQCommand(t, testCase.format, `.grants[].src[], ("x" | tonumber)`)
			if exitCode(err) != exitUsage {
				t.Fatalf("exitCode(%v) = %d, want %d", err, exitCode(err), exitUsage)
			}
			if stdout.String() != testCase.wantStdout {
				t.Errorf("stdout = %q, want %q", stdout.String(), testCase.wantStdout)
			}
		})
	}
}
