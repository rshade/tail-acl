package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunUploadsPolicy(t *testing.T) {
	t.Parallel()
	policy := `{"grants": [{"src": ["*"], "dst": ["*"]}]}`
	path := filepath.Join(t.TempDir(), "acl.json")
	if err := os.WriteFile(path, []byte(policy), 0o644); err != nil {
		t.Fatal(err)
	}

	var gotRequest *http.Request
	var gotBody string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotRequest = r.Clone(r.Context())
		b, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read request: %v", err)
		}
		gotBody = string(b)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{}`)
	}))
	defer server.Close()

	var stdout, stderr strings.Builder
	getenv := func(key string) string {
		return map[string]string{
			"TAILSCALE_API_KEY": "tskey-api-secret",
			"TAILSCALE_TAILNET": "example.com",
		}[key]
	}
	err := run(
		context.Background(),
		[]string{"--file", path, "--if-match", `"etag-1"`},
		getenv,
		server.Client(),
		server.URL,
		&stdout,
		&stderr,
	)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if gotRequest == nil {
		t.Fatal("server did not receive a request")
	}
	if gotRequest.Method != http.MethodPost {
		t.Errorf("method = %q, want POST", gotRequest.Method)
	}
	if gotRequest.URL.Path != "/api/v2/tailnet/example.com/acl" {
		t.Errorf("path = %q, want /api/v2/tailnet/example.com/acl", gotRequest.URL.Path)
	}
	username, password, ok := gotRequest.BasicAuth()
	if !ok || username != "tskey-api-secret" || password != "" {
		t.Errorf("BasicAuth = (%q, %q, %v)", username, password, ok)
	}
	if gotRequest.Header.Get("Content-Type") != "application/hujson" {
		t.Errorf("Content-Type = %q, want application/hujson", gotRequest.Header.Get("Content-Type"))
	}
	if gotRequest.Header.Get("If-Match") != `"etag-1"` {
		t.Errorf("If-Match = %q", gotRequest.Header.Get("If-Match"))
	}
	if gotBody != policy {
		t.Errorf("body = %q, want %q", gotBody, policy)
	}
	// The upload confirmation is a result: it goes to stdout, not stderr.
	if !strings.Contains(stdout.String(), "uploaded "+path+" to tailnet example.com") {
		t.Errorf("stdout = %q", stdout.String())
	}
}

func TestRunUploadsHuJSONWithCorrectContentType(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.hujson")
	if err := os.WriteFile(path, []byte("{\n// keep\n\"grants\": [],\n}"), 0o644); err != nil {
		t.Fatal(err)
	}

	var contentType string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		contentType = r.Header.Get("Content-Type")
		_, _ = io.WriteString(w, `{}`)
	}))
	defer server.Close()

	getenv := func(key string) string {
		return map[string]string{
			"TAILSCALE_API_KEY": "token",
			"TAILSCALE_TAILNET": "tailnet-id",
		}[key]
	}
	if err := run(
		context.Background(),
		[]string{"--file", path},
		getenv,
		server.Client(),
		server.URL,
		io.Discard,
		io.Discard,
	); err != nil {
		t.Fatal(err)
	}
	if contentType != "application/hujson" {
		t.Errorf("Content-Type = %q, want application/hujson", contentType)
	}
}

func TestRunReportsAPIError(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.json")
	if err := os.WriteFile(path, []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `{"message":"policy test failed"}`)
	}))
	defer server.Close()

	getenv := func(key string) string {
		return map[string]string{
			"TAILSCALE_API_KEY": "token",
			"TAILSCALE_TAILNET": "tailnet-id",
		}[key]
	}
	err := run(
		context.Background(),
		[]string{"--file", path},
		getenv,
		server.Client(),
		server.URL,
		io.Discard,
		io.Discard,
	)
	if err == nil || !strings.Contains(err.Error(), "policy test failed (400)") {
		t.Fatalf("error = %v, want API status and message", err)
	}
}

func TestRunRequiresCredentials(t *testing.T) {
	t.Parallel()
	getenv := func(string) string { return "" }
	err := run(context.Background(), nil, getenv, http.DefaultClient, defaultAPIURL, io.Discard, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "TAILSCALE_TAILNET") {
		t.Fatalf("error = %v, want missing tailnet error", err)
	}
}

// --help is a requested result under cobra and succeeds (exit 0); --not-a-flag
// is a genuine invocation error. Before the cobra conversion, stdlib flag
// returned [flag.ErrHelp] (non-nil) for --help too, so both cases used to
// share one "unexpectedly succeeded" assertion; that no longer holds for
// --help, so the two are now distinguished by wantErr. The secret-leak
// assertion is unchanged for both.
func TestFlagErrorsDoNotPrintAPIKeyFromEnvironment(t *testing.T) {
	t.Parallel()
	const secret = "tskey-api-SECRETLEAKCANARY123"
	getenv := func(key string) string {
		if key == "TAILSCALE_API_KEY" {
			return secret
		}
		return ""
	}
	tests := []struct {
		args    []string
		wantErr bool
	}{
		{[]string{"--help"}, false},
		{[]string{"--not-a-flag"}, true},
	}
	for _, tt := range tests {
		var stderr strings.Builder
		err := run(context.Background(), tt.args, getenv, http.DefaultClient, defaultAPIURL, io.Discard, &stderr)
		if (err != nil) != tt.wantErr {
			t.Errorf("run(%q) error = %v, wantErr %v", tt.args, err, tt.wantErr)
		}
		if strings.Contains(stderr.String(), secret) {
			t.Errorf("run(%q) exposed API key in stderr: %s", tt.args, stderr.String())
		}
	}
}

// TestBothDashSpellingsAccepted guards against losing single-dash long-flag
// support (-schema, -version) when the flag parser moved from stdlib flag to
// pflag; see policycore/cliflags.Normalize.
func TestBothDashSpellingsAccepted(t *testing.T) {
	t.Parallel()
	getenv := func(string) string { return "" }

	for _, args := range [][]string{{"-schema"}, {"--schema"}, {"-version"}, {"--version"}} {
		t.Run(args[0], func(t *testing.T) {
			t.Parallel()

			var stdout, stderr strings.Builder
			err := run(context.Background(), args, getenv, http.DefaultClient, defaultAPIURL, &stdout, &stderr)
			if err != nil {
				t.Fatalf("run(%q) = %v, want nil (stderr: %s)", args, err, stderr.String())
			}
			if stdout.Len() == 0 {
				t.Errorf("run(%q) wrote nothing to stdout", args)
			}
		})
	}
}
