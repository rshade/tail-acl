package tailapi_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	tailscale "tailscale.com/client/tailscale/v2"

	"github.com/rshade/tailscale-utils/tail-acl/internal/tailapi"
)

func TestUploadAndValidateFile(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.json")
	if err := os.WriteFile(path, []byte(`{"grants": []}`), 0o644); err != nil {
		t.Fatal(err)
	}

	var requests []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.Method+" "+r.URL.Path)
		if username, password, ok := r.BasicAuth(); !ok || username != "token" || password != "" {
			t.Errorf("BasicAuth = (%q, %q, %v)", username, password, ok)
		}
		if r.Header.Get("Content-Type") != "application/hujson" {
			t.Errorf("Content-Type = %q", r.Header.Get("Content-Type"))
		}
		_, _ = io.Copy(io.Discard, r.Body)
		if r.URL.Path == "/api/v2/tailnet/example.com/acl" {
			w.Header().Set("ETag", `"etag-new"`)
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
	if _, err = tailapi.ValidateFile(context.Background(), client, path); err != nil {
		t.Fatal(err)
	}
	if _, err = tailapi.UploadFile(context.Background(), client, path, `"etag"`); err != nil {
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

func TestUploadFileReturnsResponseETagAndExactBytes(t *testing.T) {
	t.Parallel()
	const policy = "// keep this comment\n{\n\t\"grants\": [],\n}\n"
	path := filepath.Join(t.TempDir(), "acl.hujson")
	if err := os.WriteFile(path, []byte(policy), 0o644); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
			return
		}
		if string(body) != policy {
			t.Errorf("upload body = %q, want exact HuJSON bytes", body)
		}
		w.Header().Set("ETag", `"etag-new"`)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	client, err := tailapi.NewClient(tailapi.Config{
		APIKey: "token", Tailnet: "example.com", BaseURL: server.URL, HTTP: server.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	uploaded, err := tailapi.UploadFile(context.Background(), client, path, `"etag-old"`)
	if err != nil {
		t.Fatal(err)
	}
	if uploaded.ETag != `"etag-new"` || string(uploaded.HuJSON) != policy {
		t.Errorf("UploadFile() = %#v", uploaded)
	}
}

func TestFetchPolicyReturnsVerbatimBodyAndETag(t *testing.T) {
	t.Parallel()
	const policy = "// keep this comment\n{\n\t\"grants\": [],\n}\n"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("ETag", "\"etag-fetch\"")
		_, _ = io.WriteString(w, policy)
	}))
	defer server.Close()
	client, err := tailapi.NewClient(tailapi.Config{
		APIKey: "token", Tailnet: "example.com", BaseURL: server.URL, HTTP: server.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	fetched, err := tailapi.FetchPolicy(context.Background(), client)
	if err != nil {
		t.Fatal(err)
	}
	if string(fetched.HuJSON) != policy || fetched.ETag != "\"etag-fetch\"" {
		t.Errorf("FetchPolicy() = %#v", fetched)
	}
}

func TestFetchPolicyReportsNonSuccess(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))
	defer server.Close()
	client, err := tailapi.NewClient(tailapi.Config{
		APIKey: "token", Tailnet: "example.com", BaseURL: server.URL, HTTP: server.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = tailapi.FetchPolicy(context.Background(), client)
	if err == nil || !strings.Contains(err.Error(), "fetching deployed policy") {
		t.Fatalf("FetchPolicy error = %v", err)
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

// serviceLookupServer answers the vip-services Get endpoint for exactly the
// escaped paths listed in answers, records every path it was asked for, and
// replies 404 with the API's JSON error shape otherwise. Routing on the wire
// path is the point: a lookup that sent the wrong name spelling gets the same
// answer a genuinely missing service does, so a test that expects "exists"
// fails rather than passing on a fabricated format it supplied itself.
func serviceLookupServer(t *testing.T, paths *[]string, answers ...string) *httptest.Server {
	t.Helper()
	known := make(map[string]bool, len(answers))
	for _, path := range answers {
		known[path] = true
	}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// EscapedPath, not Path: the server decodes %XX, so comparing Path
		// would accept a client that escaped the "svc:" colon as if it had
		// sent the colon.
		escaped := r.URL.EscapedPath()
		*paths = append(*paths, escaped)
		if !known[escaped] {
			w.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(w, `{"message":"service not found"}`)
			return
		}
		_, _ = io.WriteString(w, `{"name":"svc:known","addrs":["100.64.0.1"]}`)
	}))
}

func serviceLookupClient(t *testing.T, server *httptest.Server) *tailscale.Client {
	t.Helper()
	client, err := tailapi.NewClient(tailapi.Config{
		APIKey: "token", Tailnet: "example.com", BaseURL: server.URL, HTTP: server.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

// TestLookupServiceSendsTheSelectorSpellingVerbatim derives the request the
// pinned client builds rather than asserting it in prose: the recorded path is
// compared byte for byte, so a client that escapes the "svc:" colon, drops the
// prefix, or reroutes the endpoint fails here instead of turning every
// referenced service into a false svc-unknown in a customer's report.
func TestLookupServiceSendsTheSelectorSpellingVerbatim(t *testing.T) {
	t.Parallel()
	const wantPath = "/api/v2/tailnet/example.com/vip-services/svc:known"
	var paths []string
	server := serviceLookupServer(t, &paths, wantPath)
	defer server.Close()

	lookup, err := tailapi.LookupService(context.Background(), serviceLookupClient(t, server), "svc:known")
	if err != nil {
		t.Fatalf("LookupService error = %v, want the service found", err)
	}
	if !lookup.Exists || lookup.Name != "svc:known" {
		t.Errorf("lookup = %#v, want the svc:-prefixed name to exist", lookup)
	}
	if len(paths) != 1 || paths[0] != wantPath {
		t.Errorf("requested %q, want exactly [%q]", paths, wantPath)
	}
}

// TestLookupServiceReportsAbsenceOnReadableNotFound covers the verdict half: a
// readable 404 for the exact policy selector is absence rather than a
// collection error.
func TestLookupServiceReportsAbsenceOnReadableNotFound(t *testing.T) {
	t.Parallel()
	var paths []string
	server := serviceLookupServer(t, &paths)
	defer server.Close()

	lookup, err := tailapi.LookupService(context.Background(), serviceLookupClient(t, server), "svc:ghost")
	if err != nil {
		t.Fatalf("LookupService error = %v, want a clean not-found verdict", err)
	}
	if lookup.Exists {
		t.Errorf("lookup = %#v, want Exists false", lookup)
	}
	wantPath := "/api/v2/tailnet/example.com/vip-services/svc:ghost"
	if len(paths) != 1 || paths[0] != wantPath {
		t.Errorf("requested %q, want exactly [%q]", paths, wantPath)
	}
}

// TestLookupServiceTypesUnreadableAnswersAsUnavailable is the "does not exist"
// versus "could not check" boundary: only a 404 the client can read as the
// API's not-found is a verdict. Anything else — a rejected token, a server
// fault, or a 404 whose body this client cannot read as an API error, which is
// the shape a gateway or SSO interceptor returns — must reach the caller as a
// collection failure so lint exits 2 instead of reporting every service missing.
func TestLookupServiceTypesUnreadableAnswersAsUnavailable(t *testing.T) {
	t.Parallel()
	for _, testCase := range []struct {
		name   string
		status int
		body   string
	}{
		{name: "rejected token", status: http.StatusForbidden, body: `{"message":"forbidden"}`},
		{name: "server fault", status: http.StatusInternalServerError, body: `{"message":"boom"}`},
		{name: "unreadable 404 body", status: http.StatusNotFound, body: "<html>gateway</html>"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			var requests int
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				requests++
				w.WriteHeader(testCase.status)
				_, _ = io.WriteString(w, testCase.body)
			}))
			defer server.Close()

			lookup, err := tailapi.LookupService(
				context.Background(), serviceLookupClient(t, server), "svc:known")
			var unavailable *tailapi.ValidationUnavailableError
			if !errors.As(err, &unavailable) {
				t.Fatalf("error = %v (%T), want *ValidationUnavailableError", err, err)
			}
			if lookup.Exists {
				t.Errorf("lookup = %#v, want no verdict at all", lookup)
			}
			if requests != 1 {
				t.Errorf("requests = %d, want exactly one request for the policy selector", requests)
			}
		})
	}
}
