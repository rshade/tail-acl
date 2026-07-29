package integration_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/rshade/tailscale-utils/tail-acl/internal/aclpolicy"
)

const (
	testTailnet = "example.com"
	testAPIKey  = "tskey-api-integration-test"
)

func TestTailACLPlanValidateApplyRestoreWorkflow(t *testing.T) {
	t.Parallel()
	const originalPolicy = `// integration-test base policy
{
	"grants": [
		{"src": ["*"], "dst": ["*"], "ip": ["*"]},
	],
}
`
	const goodPolicy = `// integration-test base policy
// harmless workflow verification comment
{
	"grants": [
		{"src": ["*"], "dst": ["*"], "ip": ["*"]},
	],
}
`
	const badPolicy = `{
	"grants": [
		{"src": ["*"], "dst": ["*"], "ip": ["tcp:not-a-port"]},
	],
}
`

	tempDir := t.TempDir()
	originalPath := writePolicy(t, tempDir, "original.hujson", originalPolicy)
	goodPath := writePolicy(t, tempDir, "good.hujson", goodPolicy)
	badPath := writePolicy(t, tempDir, "bad.hujson", badPolicy)
	binary := buildTailACL(t, tempDir)

	api := newPolicyAPIServer(t, originalPolicy)
	server := httptest.NewServer(api)
	t.Cleanup(server.Close)
	runner := cliRunner{
		binary: binary,
		env: []string{
			"TAILSCALE_API_KEY=" + testAPIKey,
			"TAILSCALE_TAILNET=" + testTailnet,
			"TAILSCALE_API_URL=" + server.URL,
		},
	}

	originalETag := policyETag(originalPolicy)
	output := runner.mustSucceed(t, "--file", originalPath, "plan")
	assertContains(t, output, "plan valid; no changes", "ETag "+originalETag)

	output = runner.mustFail(t, "--file", badPath, "plan")
	assertContains(t, output, "ACL validation failed", "not-a-port")
	api.assertPolicy(t, originalPolicy)

	output = runner.mustFail(t, "--file", badPath, "--if-match", trimETag(originalETag), "upload")
	assertContains(t, output, "not-a-port", "(400)")
	api.assertPolicy(t, originalPolicy)

	output = runner.mustSucceed(t, "--file", goodPath, "plan")
	assertContains(t, output,
		"--- deployed",
		"+++ "+goodPath,
		"+// harmless workflow verification comment",
		"plan valid; changes found",
		"ETag "+originalETag,
	)

	output = runner.mustSucceed(t, "--file", goodPath, "--if-match", trimETag(originalETag), "upload")
	assertContains(t, output, "uploaded "+goodPath)
	api.assertPolicy(t, goodPolicy)

	goodETag := policyETag(goodPolicy)
	output = runner.mustSucceed(t, "--file", goodPath, "plan")
	assertContains(t, output, "plan valid; no changes", "ETag "+goodETag)

	output = runner.mustFail(t, "--file", originalPath, "--if-match", trimETag(originalETag), "upload")
	assertContains(t, output, "policy ETag does not match", "(412)")
	api.assertPolicy(t, goodPolicy)

	output = runner.mustSucceed(t, "--file", originalPath, "--if-match", trimETag(goodETag), "upload")
	assertContains(t, output, "uploaded "+originalPath)
	api.assertPolicy(t, originalPolicy)

	output = runner.mustSucceed(t, "--file", originalPath, "plan")
	assertContains(t, output, "plan valid; no changes", "ETag "+originalETag)
	api.assertRequestCounts(t, 5, 1, 1, 2)
}

func TestTailACLTypedEditPreservesSSHExtensions(t *testing.T) {
	t.Parallel()
	const originalPolicy = `{
	"ssh": [{
		"action": "accept",
		"src": ["autogroup:member"],
		"dst": ["tag:web"],
		"users": ["ubuntu"],
		"acceptEnv": ["LANG", "LC_*"]
	}],
	"sshTests": [{
		"src": "alice@example.com",
		"dst": ["tag:web"],
		"accept": ["ubuntu"],
		"check": ["root"],
		"deny": ["guest"],
		"srcPostureAttrs": {"node:os": "linux"}
	}]
}`

	tempDir := t.TempDir()
	path := writePolicy(t, tempDir, "acl.json", originalPolicy)
	runner := cliRunner{binary: buildTailACL(t, tempDir)}
	runner.mustSucceed(
		t,
		"--file", path,
		"grant", "add",
		"--src", "autogroup:member",
		"--dst", "tag:web",
		"--ip", "tcp:443",
	)

	policy, err := aclpolicy.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(policy.Grants) != 1 {
		t.Fatalf("Grants = %#v, want the authored grant", policy.Grants)
	}
	if len(policy.SSH) != 1 || len(policy.SSH[0].AcceptEnv) != 2 {
		t.Errorf("SSH = %#v, want acceptEnv preserved", policy.SSH)
	}
	if len(policy.SSHTests) != 1 ||
		len(policy.SSHTests[0].Accept) != 1 ||
		len(policy.SSHTests[0].Check) != 1 ||
		len(policy.SSHTests[0].Deny) != 1 ||
		policy.SSHTests[0].SrcPostureAttrs["node:os"] != "linux" {
		t.Errorf("SSHTests = %#v, want every assertion field preserved", policy.SSHTests)
	}
}

type cliRunner struct {
	binary string
	env    []string
}

func (r cliRunner) mustSucceed(t *testing.T, args ...string) string {
	t.Helper()
	output, err := r.run(t, args...)
	if err != nil {
		t.Fatalf("tail-acl %s failed: %v\n%s", strings.Join(args, " "), err, output)
	}
	return output
}

func (r cliRunner) mustFail(t *testing.T, args ...string) string {
	t.Helper()
	output, err := r.run(t, args...)
	if err == nil {
		t.Fatalf("tail-acl %s unexpectedly succeeded:\n%s", strings.Join(args, " "), output)
	}
	return output
}

func (r cliRunner) run(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), r.binary, args...)
	cmd.Env = append(os.Environ(), r.env...)
	output, err := cmd.CombinedOutput()
	return string(output), err
}

func buildTailACL(t *testing.T, tempDir string) string {
	t.Helper()
	moduleRoot, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(tempDir, "tail-acl")
	cmd := exec.CommandContext(t.Context(), "go", "build", "-o", binary, "./cmd/tail-acl")
	cmd.Dir = moduleRoot
	if output, buildErr := cmd.CombinedOutput(); buildErr != nil {
		t.Fatalf("building tail-acl: %v\n%s", buildErr, output)
	}
	return binary
}

func writePolicy(t *testing.T, dir, name, policy string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(policy), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func assertContains(t *testing.T, output string, values ...string) {
	t.Helper()
	for _, value := range values {
		if !strings.Contains(output, value) {
			t.Errorf("output missing %q:\n%s", value, output)
		}
	}
}

type policyAPIServer struct {
	mu             sync.Mutex
	policy         string
	validationRuns int
	rejectedWrites int
	staleWrites    int
	successWrites  int
}

func newPolicyAPIServer(t *testing.T, policy string) *policyAPIServer {
	t.Helper()
	return &policyAPIServer{policy: policy}
}

func (s *policyAPIServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	username, password, ok := r.BasicAuth()
	if !ok || username != testAPIKey || password != "" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/api/v2/tailnet/"+testTailnet+"/acl":
		s.handleGet(w)
	case r.Method == http.MethodPost && r.URL.Path == "/api/v2/tailnet/"+testTailnet+"/acl/validate":
		s.handleValidate(w, r)
	case r.Method == http.MethodPost && r.URL.Path == "/api/v2/tailnet/"+testTailnet+"/acl":
		s.handleSet(w, r)
	default:
		http.Error(w, "unexpected endpoint", http.StatusNotFound)
	}
}

func (s *policyAPIServer) handleGet(w http.ResponseWriter) {
	s.mu.Lock()
	defer s.mu.Unlock()
	w.Header().Set("Content-Type", "application/hujson")
	w.Header().Set("ETag", policyETag(s.policy))
	_, _ = io.WriteString(w, s.policy)
}

func (s *policyAPIServer) handleValidate(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	s.validationRuns++
	s.mu.Unlock()
	if message := validationError(string(body)); message != "" {
		writeAPIError(w, http.StatusOK, message)
	}
}

func (s *policyAPIServer) handleSet(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	candidate := string(body)

	s.mu.Lock()
	defer s.mu.Unlock()
	if message := validationError(candidate); message != "" {
		s.rejectedWrites++
		writeAPIError(w, http.StatusBadRequest, message)
		return
	}
	if want := policyETag(s.policy); r.Header.Get("If-Match") != want {
		s.staleWrites++
		writeAPIError(w, http.StatusPreconditionFailed, "policy ETag does not match")
		return
	}
	s.policy = candidate
	s.successWrites++
	w.WriteHeader(http.StatusOK)
}

func (s *policyAPIServer) assertPolicy(t *testing.T, want string) {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.policy != want {
		t.Errorf("deployed policy mismatch:\n%s", s.policy)
	}
}

func (s *policyAPIServer) assertRequestCounts(
	t *testing.T,
	validations, rejectedWrites, staleWrites, successWrites int,
) {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.validationRuns != validations || s.rejectedWrites != rejectedWrites || s.staleWrites != staleWrites ||
		s.successWrites != successWrites {
		t.Errorf("request counts = validation:%d rejected:%d stale:%d success:%d, want %d/%d/%d/%d",
			s.validationRuns, s.rejectedWrites, s.staleWrites, s.successWrites,
			validations, rejectedWrites, staleWrites, successWrites,
		)
	}
}

func validationError(policy string) string {
	if strings.Contains(policy, "tcp:not-a-port") {
		return `port range "not-a-port": too many dashes(-)`
	}
	return ""
}

func writeAPIError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"message": message,
		"data":    []any{},
		"status":  status,
	})
}

func policyETag(policy string) string {
	sum := sha256.Sum256([]byte(policy))
	return fmt.Sprintf("%q", hex.EncodeToString(sum[:]))
}

func trimETag(etag string) string {
	return strings.Trim(etag, `"`)
}
