package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rshade/tailscale-utils/tail-acl/internal/aclpolicy"
)

func TestTypedPolicyEdits(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.json")
	writeTestPolicy(t, path, `{}`)
	getenv := func(string) string { return "" }

	commands := [][]string{
		{"--file", path, "grant", "add", "--src", "autogroup:member", "--dst", "tag:web", "--ip", "tcp:443"},
		// Adding the same grant is idempotent.
		{"--file", path, "grant", "add", "--src", "autogroup:member", "--dst", "tag:web", "--ip", "tcp:443"},
		{"--file", path, "tag-owner", "add", "tag:web", "autogroup:admin"},
		// Adding the same owner is idempotent.
		{"--file", path, "tag-owner", "add", "tag:web", "autogroup:admin"},
		{"--file", path, "host", "set", "web", "100.64.0.10"},
	}
	for _, command := range commands {
		if err := run(
			context.Background(),
			command,
			getenv,
			http.DefaultClient,
			"",
			io.Discard,
			io.Discard,
		); err != nil {
			t.Fatalf("run(%q): %v", command, err)
		}
	}

	policy, err := aclpolicy.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(policy.Grants) != 1 {
		t.Fatalf("Grants = %#v", policy.Grants)
	}
	grant := policy.Grants[0]
	if grant.Source[0] != "autogroup:member" || grant.Destination[0] != "tag:web" || grant.IP[0] != "tcp:443" {
		t.Errorf("Grant = %#v", grant)
	}
	if owners := policy.TagOwners["tag:web"]; len(owners) != 1 || owners[0] != "autogroup:admin" {
		t.Errorf("TagOwners[tag:web] = %#v", owners)
	}
	if policy.Hosts["web"] != "100.64.0.10" {
		t.Errorf("Hosts[web] = %q", policy.Hosts["web"])
	}

	if err = run(
		context.Background(),
		[]string{"--file", path, "grant", "remove", "--index", "0"},
		getenv,
		http.DefaultClient,
		"",
		io.Discard,
		io.Discard,
	); err != nil {
		t.Fatalf("grant remove: %v", err)
	}
	policy, err = aclpolicy.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(policy.Grants) != 0 {
		t.Errorf("Grants after remove = %#v", policy.Grants)
	}
}

func TestGrantAddIgnoresFlagOrder(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.json")
	writeTestPolicy(t, path, `{
		"grants": [{
			"src": ["group:a", "group:b"],
			"dst": ["tag:x", "tag:y"],
			"ip": ["tcp:80", "tcp:443"]
		}]
	}`)

	err := run(
		context.Background(),
		[]string{
			"--file", path, "grant", "add",
			"--src", "group:b", "--src", "group:a",
			"--dst", "tag:y", "--dst", "tag:x",
			"--ip", "tcp:443", "--ip", "tcp:80",
		},
		func(string) string { return "" },
		http.DefaultClient,
		"",
		io.Discard,
		io.Discard,
	)
	if err != nil {
		t.Fatal(err)
	}

	policy, err := aclpolicy.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(policy.Grants) != 1 {
		t.Fatalf("Grants = %#v, want one order-insensitively deduplicated grant", policy.Grants)
	}
}

func TestTypedEditsRejectHuJSONWithoutChangingIt(t *testing.T) {
	t.Parallel()
	commands := [][]string{
		{"grant", "add", "--src", "autogroup:member", "--dst", "tag:web", "--ip", "tcp:443"},
		{"grant", "remove", "--index", "0"},
		{"tag-owner", "add", "tag:web", "autogroup:admin"},
		{"host", "set", "web", "100.64.0.10"},
	}
	const original = "{\n\t// operational documentation must survive\n\t\"grants\": [],\n}\n"
	for _, command := range commands {
		t.Run(strings.Join(command[:2], " "), func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "acl.hujson")
			writeTestPolicy(t, path, original)
			args := append([]string{"--file", path}, command...)
			err := run(
				context.Background(),
				args,
				func(string) string { return "" },
				http.DefaultClient,
				"",
				io.Discard,
				io.Discard,
			)
			if err == nil || !strings.Contains(err.Error(), "typed edits require a .json file") {
				t.Fatalf("error = %v, want .json requirement", err)
			}
			if code := exitCode(err); code != exitUsage {
				t.Errorf("exit code = %d, want %d for a usage error", code, exitUsage)
			}
			got, readErr := os.ReadFile(path)
			if readErr != nil {
				t.Fatal(readErr)
			}
			if string(got) != original {
				t.Errorf("HuJSON changed:\n%s", got)
			}
		})
	}
}

func TestFlagErrorsDoNotPrintAPIKeyFromEnvironment(t *testing.T) {
	t.Parallel()
	const secret = "tskey-api-SECRETLEAKCANARY123"
	getenv := func(key string) string {
		if key == "TAILSCALE_API_KEY" {
			return secret
		}
		return ""
	}
	for _, args := range [][]string{{"--help"}, {"--not-a-flag"}} {
		var stderr strings.Builder
		err := run(context.Background(), args, getenv, http.DefaultClient, "", io.Discard, &stderr)
		if err == nil {
			t.Errorf("run(%q) unexpectedly succeeded", args)
		}
		if strings.Contains(stderr.String(), secret) {
			t.Errorf("run(%q) exposed API key in stderr: %s", args, stderr.String())
		}
	}
}

func TestGrantRemoveRejectsInvalidIndex(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.json")
	writeTestPolicy(t, path, `{"grants": []}`)
	err := run(
		context.Background(),
		[]string{"--file", path, "grant", "remove", "--index", "2"},
		func(string) string { return "" },
		http.DefaultClient,
		"",
		io.Discard,
		io.Discard,
	)
	if err == nil || !strings.Contains(err.Error(), "out of range") {
		t.Fatalf("error = %v, want out-of-range error", err)
	}
	if code := exitCode(err); code != exitUsage {
		t.Errorf("exit code = %d, want %d", code, exitUsage)
	}
}

func TestMergeUsesSharedHuJSONMerge(t *testing.T) {
	t.Parallel()
	dir1 := t.TempDir()
	dir2 := t.TempDir()
	writeTestPolicy(t, filepath.Join(dir1, "base.acl.hujson"), `{
		"grants": [{"src": ["one"], "dst": ["*"], "ip": ["*"]}],
	}`)
	writeTestPolicy(t, filepath.Join(dir2, "extra.acl.json"), `{
		"grants": [{"src": ["two"], "dst": ["*"], "ip": ["*"]}]
	}`)
	out := filepath.Join(t.TempDir(), "acl.json")

	err := run(
		context.Background(),
		[]string{"--file", out, "merge", "--dir", dir1, "--dir", dir2},
		func(string) string { return "" },
		http.DefaultClient,
		"",
		io.Discard,
		io.Discard,
	)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := aclpolicy.Load(out)
	if err != nil {
		t.Fatal(err)
	}
	if len(policy.Grants) != 2 || policy.Grants[0].Source[0] != "one" || policy.Grants[1].Source[0] != "two" {
		t.Fatalf("merged Grants = %#v", policy.Grants)
	}
}

// TestJSONEnvelope asserts a command's -format json output is the versioned
// result envelope on stdout, parse-clean for machine consumers.
func TestJSONEnvelope(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	writeTestPolicy(t, filepath.Join(dir, "base.acl.hujson"), `{
		"grants": [{"src": ["one"], "dst": ["*"], "ip": ["*"]}],
	}`)
	out := filepath.Join(t.TempDir(), "acl.json")

	var stdout strings.Builder
	err := run(
		context.Background(),
		[]string{"-format", "json", "--file", out, "merge", "--dir", dir},
		func(string) string { return "" },
		http.DefaultClient,
		"",
		&stdout,
		io.Discard,
	)
	if err != nil {
		t.Fatal(err)
	}
	var res result
	if err = json.Unmarshal([]byte(stdout.String()), &res); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\n%s", err, stdout.String())
	}
	if res.SchemaVersion != schemaVersion || res.Tool != "tail-acl" || res.Command != "merge" ||
		res.Status != statusOK {
		t.Errorf("envelope = %#v", res)
	}
	if res.MergedFiles == nil || *res.MergedFiles != 1 {
		t.Errorf("MergedFiles = %v, want 1", res.MergedFiles)
	}
}

func TestVersionFlag(t *testing.T) {
	t.Parallel()
	var stdout strings.Builder
	if err := run(
		context.Background(),
		[]string{"--version"},
		func(string) string { return "" },
		http.DefaultClient,
		"",
		&stdout,
		io.Discard,
	); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(stdout.String(), "tail-acl ") {
		t.Errorf("version = %q, want a \"tail-acl \" prefix", stdout.String())
	}
}

func TestSchemaFlagIsMachineReadable(t *testing.T) {
	t.Parallel()
	var stdout strings.Builder
	if err := run(
		context.Background(),
		[]string{"-schema"},
		func(string) string { return "" },
		http.DefaultClient,
		"",
		&stdout,
		io.Discard,
	); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Name      string            `json:"name"`
		Commands  []schemaCommand   `json:"commands"`
		ExitCodes map[string]string `json:"exit_codes"`
	}
	if err := json.Unmarshal([]byte(stdout.String()), &doc); err != nil {
		t.Fatalf("schema is not valid JSON: %v\n%s", err, stdout.String())
	}
	if doc.Name != "tail-acl" || len(doc.Commands) == 0 || doc.ExitCodes["2"] == "" {
		t.Errorf("schema = %#v", doc)
	}
}

func TestExitCodeMapping(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		err  error
		want int
	}{
		{"nil", nil, exitOK},
		{"help", flag.ErrHelp, exitOK},
		{"usage", usageError{errors.New("bad flag")}, exitUsage},
		{"wrapped usage", fmt.Errorf("context: %w", usageError{errors.New("x")}), exitUsage},
		{"operation", errors.New("api failed"), exitFailed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := exitCode(tc.err); got != tc.want {
				t.Errorf("exitCode(%v) = %d, want %d", tc.err, got, tc.want)
			}
		})
	}
}

func TestValidateAndUploadUseTailscaleClient(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.json")
	writeTestPolicy(t, path, `{"grants": []}`)

	var requests []string
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.Method+" "+r.URL.Path)
		username, password, ok := r.BasicAuth()
		if !ok || username != "token" || password != "" {
			t.Errorf("BasicAuth = (%q, %q, %v)", username, password, ok)
		}
		if r.Header.Get("Content-Type") != "application/hujson" {
			t.Errorf("Content-Type = %q", r.Header.Get("Content-Type"))
		}
		_, _ = io.Copy(io.Discard, r.Body)
	}))
	defer server.Close()

	getenv := func(key string) string {
		return map[string]string{
			"TAILSCALE_API_KEY": "token",
			"TAILSCALE_TAILNET": "example.com",
		}[key]
	}
	for _, command := range [][]string{
		{"--file", path, "validate"},
		{"--file", path, "--if-match", `"etag"`, "upload"},
	} {
		if err := run(
			context.Background(),
			command,
			getenv,
			server.Client(),
			server.URL,
			io.Discard,
			io.Discard,
		); err != nil {
			t.Fatalf("run(%q): %v", command, err)
		}
	}

	want := []string{
		"POST /api/v2/tailnet/example.com/acl/validate",
		"POST /api/v2/tailnet/example.com/acl",
	}
	if len(requests) != len(want) {
		t.Fatalf("requests = %v, want %v", requests, want)
	}
	for i := range want {
		if requests[i] != want[i] {
			t.Errorf("requests[%d] = %q, want %q", i, requests[i], want[i])
		}
	}
}

func TestPlanPrintsLiveDiffWithoutUploading(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.hujson")
	writeTestPolicy(t, path, `{
		"grants": [{"src": ["*"], "dst": ["tag:web"], "ip": ["tcp:443"]}],
	}`)

	var requests []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.Method+" "+r.URL.Path)
		switch r.URL.Path {
		case "/api/v2/tailnet/example.com/acl":
			if r.Method != http.MethodGet {
				t.Errorf("policy method = %s, want GET", r.Method)
			}
			w.Header().Set("ETag", `"etag-plan"`)
			_, _ = io.WriteString(w, `{"grants": []}`)
		case "/api/v2/tailnet/example.com/acl/validate":
			if r.Method != http.MethodPost {
				t.Errorf("validate method = %s, want POST", r.Method)
			}
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()

	getenv := func(key string) string {
		return map[string]string{
			"TAILSCALE_API_KEY": "token",
			"TAILSCALE_TAILNET": "example.com",
		}[key]
	}
	var output strings.Builder
	if err := run(
		context.Background(),
		[]string{"--file", path, "plan"},
		getenv,
		server.Client(),
		server.URL,
		&output,
		io.Discard,
	); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"--- deployed",
		"+++ " + path,
		"plan valid; changes found for tailnet example.com",
		`ETag "etag-plan"`,
	} {
		if !strings.Contains(output.String(), want) {
			t.Errorf("plan output missing %q:\n%s", want, output.String())
		}
	}
	wantRequests := []string{
		"GET /api/v2/tailnet/example.com/acl",
		"POST /api/v2/tailnet/example.com/acl/validate",
	}
	if strings.Join(requests, "\n") != strings.Join(wantRequests, "\n") {
		t.Errorf("requests = %v, want %v", requests, wantRequests)
	}
}

func TestValidateRequiresCredentials(t *testing.T) {
	t.Parallel()
	err := run(
		context.Background(),
		[]string{"validate"},
		func(string) string { return "" },
		http.DefaultClient,
		"",
		io.Discard,
		io.Discard,
	)
	if err == nil || !strings.Contains(err.Error(), "TAILSCALE_TAILNET") {
		t.Fatalf("error = %v, want missing tailnet error", err)
	}
	if code := exitCode(err); code != exitUsage {
		t.Errorf("exit code = %d, want %d", code, exitUsage)
	}
}

func writeTestPolicy(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
