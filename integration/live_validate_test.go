package integration_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/mail"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tailscale/hujson"

	"github.com/rshade/tsacl/internal/tailapi"
)

const (
	liveValidateEnv       = "TSACL_LIVE"
	liveValidateCapture   = "TSACL_CAPTURE"
	liveValidateUser      = "TSACL_LIVE_USER"
	liveValidateSCIMGroup = "TSACL_LIVE_SCIM_GROUP"
	liveValidateTimeout   = 30 * time.Second
	validateTestdataDir   = "../internal/tailapi/testdata"
)

// TestLiveValidateEvidenceGate probes the response shapes that decide issue
// #52. The endpoint does not apply the submitted policy. An explicit opt-in is
// still required because tsacl credentials commonly exist in the ambient
// shell, and a plain go test ./... must never make live control-plane calls.
//
// TSACL_CAPTURE=1 writes redacted response bytes and a provenance manifest
// under internal/tailapi/testdata. Review every capture before committing it.
func TestLiveValidateEvidenceGate(t *testing.T) {
	t.Parallel()

	credentials := liveValidateCredentials(t)
	baseURL := liveValidateBaseURL(t)
	transport := newValidateOnlyTransport(baseURL, credentials.tailnet, http.DefaultTransport)
	client := &http.Client{Transport: transport, Timeout: liveValidateTimeout}
	if credentials.user == "" {
		credentials.user = liveValidateUserFromPolicy(t, client, baseURL, credentials)
	}

	probes := validationProbes(credentials.user, credentials.scimGroup)
	captures := make([]validationCapture, 0, len(probes))
	for _, probe := range probes {
		if probe.unavailable != "" {
			t.Logf("probe %s unavailable: %s", probe.name, probe.unavailable)
			captures = append(captures, validationCapture{
				Scenario:          probe.name,
				Available:         false,
				UnavailableReason: probe.unavailable,
			})
			continue
		}

		response := runValidationProbe(t, client, baseURL, credentials, probe)
		redactedRequest := redactValidationBytes(t, probe.body, credentials)
		redactedResponse := redactValidationBytes(t, response.body, credentials)
		capture := validationCapture{
			Scenario:            probe.name,
			Available:           true,
			RequestContentType:  probe.contentType,
			RequestBody:         string(redactedRequest),
			Status:              response.status,
			ResponseContentType: response.contentType,
			ResponseFile:        "validate_" + probe.name + ".json",
			ResponseBytes:       len(redactedResponse),
			ResponseSHA256:      sha256Hex(redactedResponse),
			ResponseShape:       validationResponseShape(response.body),
		}
		captures = append(captures, capture)

		if os.Getenv(liveValidateCapture) == "1" {
			writeValidationCapture(t, capture.ResponseFile, redactedResponse)
		}
		t.Logf("probe %s: status=%d content-type=%q bytes=%d shape=%s",
			probe.name, response.status, response.contentType, len(response.body), capture.ResponseShape)
		if response.status != http.StatusOK {
			t.Errorf("probe %s status = %d, want 200", probe.name, response.status)
		}
	}

	transport.assertReadOnly(t)
	if os.Getenv(liveValidateCapture) == "1" {
		writeValidationManifest(t, validationCaptureManifest{
			CapturedAt: time.Now().UTC().Format(time.RFC3339),
			Source: "live api.tailscale.com /acl/validate evidence gate via " +
				"integration/TestLiveValidateEvidenceGate",
			Redaction: "ASCII-case-insensitive substitution of the configured live user, SCIM group, " +
				"and tailnet with placeholders, then an email-shaped residue scan; all other " +
				"response bytes preserved",
			Probes: captures,
		})
		t.Logf("wrote validation captures to %s; review them and update the provenance README", validateTestdataDir)
	}
}

// TestLiveValidateProductionClassifier proves the owned production request
// builder and classifier—not only the capture harness—against the live control
// plane. It exercises one rejection and one healthy policy through
// tailapi.ValidatePolicy while the same fail-closed transport prevents any
// mutation endpoint from being reached.
func TestLiveValidateProductionClassifier(t *testing.T) {
	t.Parallel()

	credentials := liveValidateCredentials(t)
	baseURL := liveValidateBaseURL(t)
	transport := newValidateOnlyTransport(baseURL, credentials.tailnet, http.DefaultTransport)
	httpClient := &http.Client{Transport: transport, Timeout: liveValidateTimeout}
	if credentials.user == "" {
		credentials.user = liveValidateUserFromPolicy(t, httpClient, baseURL, credentials)
	}
	client, err := tailapi.NewClient(tailapi.Config{
		APIKey:  credentials.apiKey,
		Tailnet: credentials.tailnet,
		BaseURL: baseURL.String(),
		HTTP:    httpClient,
	})
	if err != nil {
		t.Fatal(err)
	}

	probes := validationProbes(credentials.user, credentials.scimGroup)
	failing := probeByName(t, probes, "b_policy_test_failure")
	failureResult, err := tailapi.ValidatePolicy(t.Context(), client, failing.body)
	var validationErr *tailapi.ValidationError
	if !errors.As(err, &validationErr) {
		t.Fatalf("live failing policy error = %s, want *tailapi.ValidationError", errShape(err))
	}
	// Assertions report shape, never content: ValidationDetail.User carries the
	// real identity this harness derives without displaying, and t.Errorf output
	// is exactly what gets pasted into a bug report.
	firstDetailErrors := 0
	if len(validationErr.Data) != 0 {
		firstDetailErrors = len(validationErr.Data[0].Errors)
	}
	if validationErr.Status != http.StatusOK || validationErr.Message == "" ||
		len(validationErr.Data) == 0 || firstDetailErrors == 0 ||
		len(failureResult.Failures) == 0 {
		t.Errorf("live failing policy: status=%d message-present=%v details=%d first-detail-errors=%d "+
			"failures=%d; want HTTP 200 with a message and one populated error detail",
			validationErr.Status, validationErr.Message != "", len(validationErr.Data),
			firstDetailErrors, len(failureResult.Failures))
	}

	healthy := probeByName(t, probes, "e_healthy")
	healthyResult, err := tailapi.ValidatePolicy(t.Context(), client, healthy.body)
	if err != nil {
		t.Fatalf("live healthy policy failed: %s", errShape(err))
	}
	if healthyResult.Message != "" || len(healthyResult.Failures) != 0 || len(healthyResult.Warnings) != 0 {
		t.Errorf("live healthy policy: message-present=%v failures=%d warnings=%d, want a clean validation",
			healthyResult.Message != "", len(healthyResult.Failures), len(healthyResult.Warnings))
	}
	transport.assertReadOnly(t)
}

func probeByName(t *testing.T, probes []validationProbe, name string) validationProbe {
	t.Helper()
	for _, probe := range probes {
		if probe.name == name {
			return probe
		}
	}
	t.Fatalf("validation probe %q not found", name)
	return validationProbe{}
}

type liveValidationCredentials struct {
	apiKey    string
	tailnet   string
	user      string
	scimGroup string
}

func liveValidateCredentials(t *testing.T) liveValidationCredentials {
	t.Helper()
	if os.Getenv(liveValidateEnv) != "1" {
		t.Skipf("set %s=1 with scratch-tailnet credentials to run the live control-plane gates",
			liveValidateEnv)
	}
	credentials := liveValidationCredentials{
		apiKey:    os.Getenv("TAILSCALE_API_KEY"),
		tailnet:   os.Getenv("TAILSCALE_TAILNET"),
		user:      os.Getenv(liveValidateUser),
		scimGroup: os.Getenv(liveValidateSCIMGroup),
	}
	if credentials.apiKey == "" || credentials.tailnet == "" {
		t.Fatalf("TAILSCALE_API_KEY and TAILSCALE_TAILNET are required when %s=1", liveValidateEnv)
	}
	return credentials
}

func liveValidateBaseURL(t *testing.T) *url.URL {
	t.Helper()
	value := os.Getenv("TAILSCALE_API_URL")
	if value == "" {
		value = "https://api.tailscale.com"
	}
	parsed, err := url.Parse(value)
	if err != nil {
		t.Fatalf("parse TAILSCALE_API_URL: %v", err)
	}
	return parsed
}

// liveValidateUserFromPolicy keeps discovery on the issue's read-only
// allowlist. It extracts a concrete email-valued selector from the deployed
// policy without printing or persisting the identity. TSACL_LIVE_USER remains
// the explicit fallback for policies expressed entirely through autogroups.
func liveValidateUserFromPolicy(
	t *testing.T,
	client *http.Client,
	baseURL *url.URL,
	credentials liveValidationCredentials,
) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), liveValidateTimeout)
	defer cancel()
	endpoint := baseURL.JoinPath("/api/v2", "tailnet", url.PathEscape(credentials.tailnet), "acl")
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		t.Fatalf("build policy discovery request: %v", err)
	}
	request.SetBasicAuth(credentials.apiKey, "")
	request.Header.Set("Accept", "application/hujson")
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("fetch deployed policy to derive %s: %s", liveValidateUser, errShape(err))
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read deployed policy to derive %s: %s", liveValidateUser, errShape(err))
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("fetch deployed policy to derive %s: HTTP %d", liveValidateUser, response.StatusCode)
	}
	users, err := concretePolicyUsers(body)
	if err != nil {
		t.Fatalf("parse deployed policy to derive %s: %s", liveValidateUser, errShape(err))
	}
	if len(users) == 0 {
		t.Fatalf("deployed policy contains no concrete email selector; set %s explicitly", liveValidateUser)
	}
	t.Logf("derived %s from the deployed policy without displaying it", liveValidateUser)
	return users[0]
}

func concretePolicyUsers(policy []byte) ([]string, error) {
	standard, err := hujson.Standardize(policy)
	if err != nil {
		return nil, fmt.Errorf("standardize HuJSON: %w", err)
	}
	var value any
	if err = json.Unmarshal(standard, &value); err != nil {
		return nil, fmt.Errorf("decode policy JSON: %w", err)
	}
	unique := make(map[string]struct{})
	collectConcretePolicyUsers(value, unique)
	users := make([]string, 0, len(unique))
	for user := range unique {
		users = append(users, user)
	}
	sort.Strings(users)
	return users, nil
}

func collectConcretePolicyUsers(value any, users map[string]struct{}) {
	switch typed := value.(type) {
	case map[string]any:
		for _, child := range typed {
			collectConcretePolicyUsers(child, users)
		}
	case []any:
		for _, child := range typed {
			collectConcretePolicyUsers(child, users)
		}
	case string:
		if strings.HasPrefix(typed, "group:") {
			return
		}
		address, err := mail.ParseAddress(typed)
		if err == nil && address.Address == typed && strings.Contains(typed, "@") {
			users[typed] = struct{}{}
		}
	}
}

type validationProbe struct {
	name        string
	contentType string
	body        []byte
	unavailable string
}

func validationProbes(user, scimGroup string) []validationProbe {
	quotedUser := strconv.Quote(user)
	probes := []validationProbe{
		{
			name:        "a_tests_array_failure",
			contentType: "application/json",
			body: fmt.Appendf(nil,
				`[{"src":%s,"accept":["100.64.0.1:22"],"deny":["100.64.0.1:22"]}]`,
				quotedUser,
			),
		},
		{
			name:        "b_policy_test_failure",
			contentType: "application/hujson",
			body: fmt.Appendf(nil, `{
  "acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}],
  "tests": [{"src": %s, "deny": ["100.64.0.1:22"]}],
}`, quotedUser),
		},
		{
			name:        "b_prime_unknown_source",
			contentType: "application/hujson",
			body: []byte(`{
  "acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}],
  "tests": [{"src": "not-a-user-or-host", "deny": ["100.64.0.1:22"]}],
}`),
		},
		{
			name:        "d_parse_error",
			contentType: "application/hujson",
			body:        []byte(`{"grants": [`),
		},
		{
			name:        "e_healthy",
			contentType: "application/hujson",
			body:        []byte("{\n  \"grants\": [],\n}\n"),
		},
	}

	scimProbe := validationProbe{name: "c_scim_warning", contentType: "application/hujson"}
	if scimGroup == "" {
		scimProbe.unavailable = liveValidateSCIMGroup + " is unset; no SCIM warning channel was inferred"
	} else {
		scimProbe.body = fmt.Appendf(nil, `{
  "acls": [{"action": "accept", "src": [%s], "dst": ["*:*"]}],
}`, strconv.Quote(scimGroup))
	}
	return slices.Insert(probes, 3, scimProbe)
}

type validationProbeResponse struct {
	status      int
	contentType string
	body        []byte
}

func runValidationProbe(
	t *testing.T,
	client *http.Client,
	baseURL *url.URL,
	credentials liveValidationCredentials,
	probe validationProbe,
) validationProbeResponse {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), liveValidateTimeout)
	defer cancel()
	endpoint := baseURL.JoinPath(
		"/api/v2", "tailnet", url.PathEscape(credentials.tailnet), "acl", "validate",
	)
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), bytes.NewReader(probe.body))
	if err != nil {
		t.Fatalf("build probe %s request: %v", probe.name, err)
	}
	request.SetBasicAuth(credentials.apiKey, "")
	request.Header.Set("Content-Type", probe.contentType)

	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("run probe %s: %v", probe.name, err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read probe %s response: %v", probe.name, err)
	}
	return validationProbeResponse{
		status:      response.StatusCode,
		contentType: response.Header.Get("Content-Type"),
		body:        body,
	}
}

// minRedactableLength keeps substring substitution from rewriting evidence. The
// v2 client's default tailnet is "-", which occurs inside ordinary probe text
// such as "not-a-user-or-host"; substituting it would corrupt the capture while
// redacting nothing.
const minRedactableLength = 4

func redactValidationBytes(
	t *testing.T,
	data []byte,
	credentials liveValidationCredentials,
) []byte {
	t.Helper()
	redacted := bytes.Clone(data)
	type replacement struct {
		source      string
		value       string
		placeholder string
	}
	identities := []replacement{
		{liveValidateUser, credentials.user, "<user-1>"},
		{liveValidateSCIMGroup, credentials.scimGroup, "<scim-group-1>"},
	}
	tailnet := replacement{"TAILSCALE_TAILNET", credentials.tailnet, "<tailnet>"}
	apply := func(one replacement) {
		if one.value == "" {
			return
		}
		if len(one.value) < minRedactableLength {
			t.Fatalf("%s is %d bytes, too short to redact by substitution without corrupting "+
				"unrelated capture bytes; capture from a tailnet whose name is distinctive",
				one.source, len(one.value))
		}
		redacted = replaceASCIIFold(redacted, one.value, one.placeholder)
	}
	for _, identity := range identities {
		apply(identity)
	}
	// The scan runs before the tailnet substitution, not after it. A tailnet is
	// usually the identity domain too, so replacing it first rewrites an
	// undeclared "bob@<tailnet-name>" into "bob@<tailnet>" — which no longer
	// matches an email shape, leaving the guard unable to fire on the very leak
	// it exists to catch while the login's local part still reaches the fixture.
	assertNoResidualIdentity(t, redacted)
	apply(tailnet)
	return redacted
}

// replaceASCIIFold replaces every case-insensitive occurrence of old. The
// control plane normalizes logins, so a mixed-case TSACL_LIVE_USER must
// still match the lowercase identity the server echoes back. Folding is ASCII
// only so the lowered copy stays byte-aligned with the original, which
// [bytes.ToLower] does not guarantee for every rune.
func replaceASCIIFold(data []byte, old, placeholder string) []byte {
	target := asciiLower([]byte(old))
	lowered := asciiLower(data)
	var out []byte
	for {
		index := bytes.Index(lowered, target)
		if index < 0 {
			return append(out, data...)
		}
		out = append(out, data[:index]...)
		out = append(out, placeholder...)
		data = data[index+len(target):]
		lowered = lowered[index+len(target):]
	}
}

func asciiLower(data []byte) []byte {
	lowered := bytes.Clone(data)
	for i, b := range lowered {
		if b >= 'A' && b <= 'Z' {
			lowered[i] = b + ('a' - 'A')
		}
	}
	return lowered
}

// validationIdentityPattern matches an email-shaped identity in redacted bytes.
// It is the leak check that re-searching for a just-replaced value cannot be:
// [bytes.Index] always finds every occurrence of what it was given, so looking
// for that same value again proves nothing. What can actually reach a committed
// fixture is an identity the harness was never told about — a SCIM group
// member, a device owner, or a login the server names in prose.
var validationIdentityPattern = regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}`)

// assertNoResidualIdentity fails without printing the match: reporting the leak
// verbatim would put the identity in test output, which is the thing the
// harness exists to prevent.
func assertNoResidualIdentity(t *testing.T, redacted []byte) {
	t.Helper()
	for _, span := range validationIdentityPattern.FindAllIndex(redacted, -1) {
		t.Fatalf("capture still holds an email-shaped identity after redaction "+
			"(%d bytes at offset %d); add it to the redaction set before capturing",
			span[1]-span[0], span[0])
	}
}

func validationResponseShape(body []byte) string {
	if len(body) == 0 {
		return "empty-body"
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(body, &object); err != nil || object == nil {
		return "non-object-json-or-invalid"
	}
	return "object,message=" + jsonValueShape(object["message"]) + ",data=" + jsonValueShape(object["data"])
}

func jsonValueShape(raw json.RawMessage) string {
	if raw == nil {
		return "absent"
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return "null"
	}
	var text string
	if err := json.Unmarshal(raw, &text); err == nil {
		if text == "" {
			return "empty-string"
		}
		return "non-empty-string"
	}
	var values []json.RawMessage
	if err := json.Unmarshal(raw, &values); err == nil {
		if len(values) == 0 {
			return "empty-array"
		}
		return "non-empty-array"
	}
	return "other"
}

type validationCapture struct {
	Scenario            string `json:"scenario"`
	Available           bool   `json:"available"`
	UnavailableReason   string `json:"unavailable_reason,omitempty"`
	RequestContentType  string `json:"request_content_type,omitempty"`
	RequestBody         string `json:"request_body,omitempty"`
	Status              int    `json:"status,omitempty"`
	ResponseContentType string `json:"response_content_type,omitempty"`
	ResponseFile        string `json:"response_file,omitempty"`
	ResponseBytes       int    `json:"response_bytes,omitempty"`
	ResponseSHA256      string `json:"response_sha256,omitempty"`
	ResponseShape       string `json:"response_shape,omitempty"`
}

type validationCaptureManifest struct {
	CapturedAt string              `json:"captured_at"`
	Source     string              `json:"source"`
	Redaction  string              `json:"redaction"`
	Probes     []validationCapture `json:"probes"`
}

func writeValidationCapture(t *testing.T, name string, data []byte) {
	t.Helper()
	path := filepath.Join(validateTestdataDir, name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func writeValidationManifest(t *testing.T, manifest validationCaptureManifest) {
	t.Helper()
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatalf("marshal validation capture manifest: %v", err)
	}
	data = append(data, '\n')
	writeValidationCapture(t, "validate_capture_manifest.json", data)
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// validateOnlyTransport permits only the read-only policy fetch and validation
// calls used by this evidence gate. It rejects redirects or regressions to any
// policy mutation before they reach the live control plane.
type validateOnlyTransport struct {
	base         http.RoundTripper
	host         string
	validatePath string
	policyPath   string

	mu       sync.Mutex
	requests []string
}

func newValidateOnlyTransport(
	baseURL *url.URL,
	tailnet string,
	base http.RoundTripper,
) *validateOnlyTransport {
	if base == nil {
		base = http.DefaultTransport
	}
	validateURL := baseURL.JoinPath("/api/v2", "tailnet", url.PathEscape(tailnet), "acl", "validate")
	policyURL := baseURL.JoinPath("/api/v2", "tailnet", url.PathEscape(tailnet), "acl")
	return &validateOnlyTransport{
		base:         base,
		host:         baseURL.Host,
		validatePath: requestEscapedPath(validateURL),
		policyPath:   requestEscapedPath(policyURL),
	}
}

// [url.URL.JoinPath] can retain a relative Path for a host-only base URL even
// though URL.String correctly emits an absolute request path. Normalize to the
// path [http.NewRequest] will parse so the transport compares like with like.
func requestEscapedPath(endpoint *url.URL) string {
	path := endpoint.EscapedPath()
	if strings.HasPrefix(path, "/") {
		return path
	}
	return "/" + path
}

func (transport *validateOnlyTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	entry := request.Method + " " + request.URL.EscapedPath()
	transport.mu.Lock()
	transport.requests = append(transport.requests, entry)
	transport.mu.Unlock()

	hostMatch := request.URL.Host == transport.host
	validatePathMatch := request.URL.EscapedPath() == transport.validatePath
	policyPathMatch := request.URL.EscapedPath() == transport.policyPath
	allowed := hostMatch &&
		((request.Method == http.MethodPost && validatePathMatch) ||
			(request.Method == http.MethodGet && policyPathMatch))
	if !allowed {
		if request.Body != nil {
			_ = request.Body.Close()
		}
		return nil, fmt.Errorf(
			"validation evidence-gate violation: method=%s host_match=%t validate_path_match=%t policy_path_match=%t",
			request.Method,
			hostMatch,
			validatePathMatch,
			policyPathMatch,
		)
	}
	return transport.base.RoundTrip(request)
}

func (transport *validateOnlyTransport) assertReadOnly(t *testing.T) {
	t.Helper()
	transport.mu.Lock()
	defer transport.mu.Unlock()
	if len(transport.requests) == 0 {
		t.Fatal("validation evidence gate made no requests")
	}
	for _, request := range transport.requests {
		if !strings.HasPrefix(request, http.MethodPost+" ") &&
			!strings.HasPrefix(request, http.MethodGet+" ") {
			t.Errorf("request = %q, want POST validate or GET policy only", request)
		}
	}
}

func TestValidationResponseShape(t *testing.T) {
	t.Parallel()
	testCases := []struct {
		name string
		body string
		want string
	}{
		{"zero bytes", "", "empty-body"},
		{"empty object", `{}`, "object,message=absent,data=absent"},
		{"empty message null data", `{"message":"","data":null}`,
			"object,message=empty-string,data=null"},
		{"data only", `{"data":[{"user":"u","errors":["failed"]}]}`,
			"object,message=absent,data=non-empty-array"},
		{"warning", `{"message":"warning(s) found","data":[]}`,
			"object,message=non-empty-string,data=empty-array"},
		{"array", `[]`, "non-object-json-or-invalid"},
		{"null", `null`, "non-object-json-or-invalid"},
		{"invalid", `not json`, "non-object-json-or-invalid"},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			if got := validationResponseShape([]byte(testCase.body)); got != testCase.want {
				t.Errorf("validationResponseShape(%q) = %q, want %q", testCase.body, got, testCase.want)
			}
		})
	}
}

func TestRedactValidationBytesPreservesOtherBytes(t *testing.T) {
	t.Parallel()
	credentials := liveValidationCredentials{
		tailnet:   "real.example.com",
		user:      "alice@example.com",
		scimGroup: "group:staff@example.com",
	}
	body := []byte("{\r\n  \"user\": \"alice@example.com\", " +
		"\"warnings\": [\"group:staff@example.com in real.example.com\"]\r\n}\r\n")
	want := "{\r\n  \"user\": \"<user-1>\", " +
		"\"warnings\": [\"<scim-group-1> in <tailnet>\"]\r\n}\r\n"
	if got := string(redactValidationBytes(t, body, credentials)); got != want {
		t.Errorf("redacted bytes = %q, want %q", got, want)
	}
}

func TestConcretePolicyUsers(t *testing.T) {
	t.Parallel()
	policy := []byte(`{
  // ignored-comment@example.com must not become a probe identity.
  "groups": {
    "group:staff@example.com": ["zoe@example.com", "alice@example.com"],
  },
  "acls": [{
    "action": "accept",
    "src": ["alice@example.com", "group:staff@example.com", "autogroup:member"],
    "dst": ["*:*"],
  }],
}`)
	users, err := concretePolicyUsers(policy)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"alice@example.com", "zoe@example.com"}
	if !slices.Equal(users, want) {
		t.Errorf("concretePolicyUsers = %v, want %v", users, want)
	}
}

func TestValidateOnlyTransportFailsClosed(t *testing.T) {
	t.Parallel()
	baseURL, err := url.Parse("https://api.example.test/prefix")
	if err != nil {
		t.Fatal(err)
	}
	var forwarded []string
	base := roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		forwarded = append(forwarded, request.Method+" "+request.URL.EscapedPath())
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader("")),
			Request:    request,
		}, nil
	})
	transport := newValidateOnlyTransport(baseURL, "example.com", base)

	allowed := []struct {
		method string
		path   string
	}{
		{http.MethodPost, "/prefix/api/v2/tailnet/example.com/acl/validate"},
		{http.MethodGet, "/prefix/api/v2/tailnet/example.com/acl"},
	}
	for _, request := range allowed {
		req, requestErr := http.NewRequest(request.method, "https://api.example.test"+request.path, nil)
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		response, requestErr := transport.RoundTrip(req)
		if requestErr != nil {
			t.Errorf("allowed request %s %s: %v", request.method, request.path, requestErr)
			continue
		}
		_ = response.Body.Close()
	}

	denied := []struct {
		method string
		url    string
	}{
		{http.MethodPost, "https://api.example.test/prefix/api/v2/tailnet/example.com/acl"},
		{http.MethodDelete, "https://api.example.test/prefix/api/v2/tailnet/example.com/acl/validate"},
		{http.MethodPost, "https://redirected.example.test/prefix/api/v2/tailnet/example.com/acl/validate"},
	}
	for _, request := range denied {
		req, requestErr := http.NewRequest(request.method, request.url, nil)
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		if _, requestErr = transport.RoundTrip(req); requestErr == nil {
			t.Errorf("denied request %s %s reached base transport", request.method, request.url)
		}
	}
	if want := []string{
		"POST /prefix/api/v2/tailnet/example.com/acl/validate",
		"GET /prefix/api/v2/tailnet/example.com/acl",
	}; !slices.Equal(forwarded, want) {
		t.Errorf("forwarded = %v, want %v", forwarded, want)
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (fn roundTripperFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return fn(request)
}
