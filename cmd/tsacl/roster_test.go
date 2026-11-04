package main

import (
	"bytes"
	"context"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
)

func TestRosterAppliesOnlyToTestAndCheck(t *testing.T) {
	t.Parallel()
	// A silently ignored roster means the operator believes role autogroups
	// were resolved when they were not, which is the confusion this flag
	// exists to remove. Rejecting is the whole point, so every non-consumer
	// must reject -- including leaf subcommands, whose cmd.Name() is the short
	// name ("add", "set"), which is why the check must be an allowlist.
	rejected := [][]string{
		{"--roster", filepath.Join("testdata", "roster.json"), "plan"},
		{"--roster", filepath.Join("testdata", "roster.json"), "lint"},
		{"--roster", filepath.Join("testdata", "roster.json"), "validate"},
		{"--roster", filepath.Join("testdata", "roster.json"), "pull"},
		{"--roster", filepath.Join("testdata", "roster.json"), "posture", "set", "n", "e"},
		{"--roster", filepath.Join("testdata", "roster.json"), "grant", "remove", "--index", "0"},
	}
	for _, args := range rejected {
		t.Run(strings.Join(args[2:], " "), func(t *testing.T) {
			t.Parallel()
			var stdout, stderr bytes.Buffer
			err := run(context.Background(), args, func(string) string { return "" },
				&http.Client{}, "https://api.example.com", &stdout, &stderr)
			if err == nil {
				t.Fatalf("--roster on %v was accepted; want a usage error", args[2:])
			}
			if !strings.Contains(err.Error(), "--roster applies only to test and check") {
				t.Errorf("error = %q, want it to name the restriction", err)
			}
		})
	}
}

func TestRosterLoadFailureIsFatal(t *testing.T) {
	t.Parallel()
	// Degrading to roster-blind would turn a typo'd path into a silent exit 10
	// rather than a fixable error.
	//
	// Each case pins the SPECIFIC message, not merely "an error happened". A
	// bare non-nil check would pass before this flag existed at all, because an
	// unrecognised --roster produces cobra's "unknown flag" error — a test that
	// green-lights the feature being absent.
	tests := []struct {
		name     string
		contents string
		contains string
	}{
		{name: "missing", contents: "", contains: "could not read --roster"},
		{name: "malformed", contents: `{"ada@example.com": `, contains: "could not load --roster"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			rosterPath := filepath.Join(t.TempDir(), "roster.json")
			if test.name == "malformed" {
				writeTestPolicy(t, rosterPath, test.contents)
			}
			policyPath := filepath.Join(t.TempDir(), "acl.hujson")
			writeTestPolicy(t, policyPath, `{"grants": [{"src": ["*"], "dst": ["*"], "ip": ["*"]}]}`)

			var stdout, stderr bytes.Buffer
			err := run(context.Background(),
				[]string{"--roster", rosterPath, "--file", policyPath, "test"},
				func(string) string { return "" },
				&http.Client{}, "https://api.example.com", &stdout, &stderr)
			if err == nil {
				t.Fatal("a bad roster was accepted; want a fatal error")
			}
			if !strings.Contains(err.Error(), test.contains) {
				t.Errorf("error = %q, want it to contain %q", err, test.contains)
			}
		})
	}
}

func TestRosterLoginsNeverLeakIntoOutput(t *testing.T) {
	t.Parallel()
	// A role autogroup matches only when the query IS the login, so the only
	// login that can reach output is one the operator already supplied. This
	// guards that property against a future change that enumerates the roster.
	//
	// The run must SUCCEED and produce output, and that is asserted rather than
	// assumed. Ignoring the error would make this pass vacuously: a run that
	// died on an unknown flag, an unreadable policy, or a failed assertion emits
	// nothing, and "the canary is absent from an empty buffer" proves nothing at
	// all. The policy therefore declares a test that passes.
	policyPath := filepath.Join(t.TempDir(), "acl.hujson")
	writeTestPolicy(t, policyPath, `{
		"grants": [{"src": ["alice@example.com"], "dst": ["tag:web"], "ip": ["tcp:443"]}],
		"tagOwners": {"tag:web": ["autogroup:admin"]},
		"tests": [{"src": "alice@example.com", "accept": ["tag:web:443"]}]
	}`)

	var stdout, stderr bytes.Buffer
	err := run(context.Background(),
		[]string{
			"--roster", filepath.Join("testdata", "roster.json"),
			"--file", policyPath,
			"--format", "json", "test",
		},
		func(string) string { return "" },
		&http.Client{}, "https://api.example.com", &stdout, &stderr)
	if err != nil {
		t.Fatalf("run returned %v (stderr: %s)", err, stderr.String())
	}
	if !strings.Contains(stdout.String(), "schema_version") {
		t.Fatalf("stdout carries no result envelope, so the canary check proves nothing: %s", stdout.String())
	}
	for _, stream := range []struct {
		name string
		text string
	}{{"stdout", stdout.String()}, {"stderr", stderr.String()}} {
		if strings.Contains(stream.text, "unused@example.com") {
			t.Errorf("a roster login never queried appeared in %s: %s", stream.name, stream.text)
		}
	}
}

func TestEmptyRosterPathIsRejected(t *testing.T) {
	t.Parallel()
	// --roster "" must not read as "no roster supplied". A CI script passing an
	// unset variable would otherwise get a silent roster-blind run rather than
	// a fixable error.
	policyPath := filepath.Join(t.TempDir(), "acl.hujson")
	writeTestPolicy(t, policyPath, `{"grants": [{"src": ["*"], "dst": ["*"], "ip": ["*"]}]}`)

	var stdout, stderr bytes.Buffer
	err := run(context.Background(),
		[]string{"--roster", "", "--file", policyPath, "test"},
		func(string) string { return "" },
		&http.Client{}, "https://api.example.com", &stdout, &stderr)
	if err == nil {
		t.Fatal(`--roster "" was accepted; want a usage error`)
	}
	if !strings.Contains(err.Error(), "--roster requires a path") {
		t.Errorf("error = %q, want it to name the empty value", err)
	}
	if exitCode(err) != exitUsage {
		t.Errorf("exit = %d, want %d", exitCode(err), exitUsage)
	}
}
