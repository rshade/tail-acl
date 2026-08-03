package tailapi_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rshade/tailscale-utils/tail-acl/internal/tailapi"
)

func TestUploadAndValidateFile(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.json")
	if err := os.WriteFile(path, []byte(`{"grants": []}`), 0o644); err != nil {
		t.Fatal(err)
	}

	var requests []string
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.Method+" "+r.URL.Path)
		if username, password, ok := r.BasicAuth(); !ok || username != "token" || password != "" {
			t.Errorf("BasicAuth = (%q, %q, %v)", username, password, ok)
		}
		if r.Header.Get("Content-Type") != "application/hujson" {
			t.Errorf("Content-Type = %q", r.Header.Get("Content-Type"))
		}
		_, _ = io.Copy(io.Discard, r.Body)
	}))
	defer server.Close()

	client, err := tailapi.NewClient(tailapi.Config{
		APIKey:  "token",
		Tailnet: "example.com",
		BaseURL: server.URL,
		HTTP:    server.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = tailapi.ValidateFile(context.Background(), client, path); err != nil {
		t.Fatal(err)
	}
	if err = tailapi.UploadFile(context.Background(), client, path, `"etag"`); err != nil {
		t.Fatal(err)
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

func TestPlanFileReturnsValidatedUnifiedDiffAndETag(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "candidate.hujson")
	if err := os.WriteFile(path, []byte(`{
		"grants": [{"src": ["*"], "dst": ["tag:web"], "ip": ["tcp:443"]}],
	}`), 0o644); err != nil {
		t.Fatal(err)
	}

	var requests []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.Method+" "+r.URL.Path)
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v2/tailnet/example.com/acl":
			w.Header().Set("ETag", `"etag-7"`)
			_, _ = io.WriteString(w, `{"grants": []}`)
		case r.Method == http.MethodPost && r.URL.Path == "/api/v2/tailnet/example.com/acl/validate":
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Error(err)
			}
			if !strings.Contains(string(body), `"tag:web"`) {
				t.Errorf("validation body = %q, want candidate policy", body)
			}
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			http.Error(w, "unexpected request", http.StatusInternalServerError)
		}
	}))
	defer server.Close()

	client, err := tailapi.NewClient(tailapi.Config{
		APIKey:  "token",
		Tailnet: "example.com",
		BaseURL: server.URL,
		HTTP:    server.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := tailapi.PlanFile(context.Background(), client, path)
	if err != nil {
		t.Fatal(err)
	}
	if !plan.Changed {
		t.Fatal("plan.Changed = false, want true")
	}
	if plan.ETag != `"etag-7"` {
		t.Errorf("plan.ETag = %q, want quoted ETag", plan.ETag)
	}
	for _, want := range []string{"--- deployed", "+++ " + path, "+\t\"grants\": [{\"src\": [\"*\"], \"dst\": [\"tag:web\"], \"ip\": [\"tcp:443\"]}],"} {
		if !strings.Contains(plan.Diff, want) {
			t.Errorf("diff missing %q:\n%s", want, plan.Diff)
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

func TestPlanFileReportsNoChangesForMatchingPolicy(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "candidate.json")
	if err := os.WriteFile(path, []byte("{\n\t\"grants\": []\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.Header().Set("ETag", `"etag-same"`)
			_, _ = io.WriteString(w, "{\n\t\"grants\": []\n}\n")
		}
	}))
	defer server.Close()
	client, err := tailapi.NewClient(
		tailapi.Config{APIKey: "token", Tailnet: "example.com", BaseURL: server.URL, HTTP: server.Client()},
	)
	if err != nil {
		t.Fatal(err)
	}

	plan, err := tailapi.PlanFile(context.Background(), client, path)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Changed || plan.Diff != "" {
		t.Errorf("matching plan = %#v, want no changes", plan)
	}
}

func TestPlanFileStopsOnValidationFailure(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "candidate.json")
	if err := os.WriteFile(path, []byte(`{"grants": []}`), 0o644); err != nil {
		t.Fatal(err)
	}

	var requests []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.Method+" "+r.URL.Path)
		if r.Method == http.MethodGet {
			_, _ = io.WriteString(w, `{"grants": []}`)
			return
		}
		_, _ = io.WriteString(w, `{"message":"test(s) failed","data":[]}`)
	}))
	defer server.Close()
	client, err := tailapi.NewClient(
		tailapi.Config{APIKey: "token", Tailnet: "example.com", BaseURL: server.URL, HTTP: server.Client()},
	)
	if err != nil {
		t.Fatal(err)
	}

	plan, err := tailapi.PlanFile(context.Background(), client, path)
	if err == nil || !strings.Contains(err.Error(), "test(s) failed") {
		t.Fatalf("error = %v, want policy-test failure", err)
	}
	if plan == nil || plan.Validation.Message != "test(s) failed" {
		t.Errorf("plan = %#v, want partial validation result after failure", plan)
	}
	for _, request := range requests {
		if request == "POST /api/v2/tailnet/example.com/acl" {
			t.Fatal("plan called the policy upload endpoint")
		}
	}
}
