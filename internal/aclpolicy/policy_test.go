package aclpolicy_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	tailscale "tailscale.com/client/tailscale/v2"

	"github.com/rshade/tailscale-utils/tail-acl/internal/aclpolicy"
)

func TestLoadHuJSONIntoTailscaleTypes(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.hujson")
	writeFile(t, path, `{
		// typed policy input
		"grants": [{"src": ["a"], "dst": ["b"], "ip": ["tcp:443"]}],
		"tagOwners": {"tag:web": ["autogroup:admin"]},
		"hosts": {"web": "100.64.0.10"},
	}`)

	policy, err := aclpolicy.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(policy.Grants) != 1 || policy.Grants[0].IP[0] != "tcp:443" {
		t.Fatalf("Grants = %#v", policy.Grants)
	}
	if policy.TagOwners["tag:web"][0] != "autogroup:admin" {
		t.Fatalf("TagOwners = %#v", policy.TagOwners)
	}
	if policy.Hosts["web"] != "100.64.0.10" {
		t.Fatalf("Hosts = %#v", policy.Hosts)
	}
}

func TestLoadRejectsUnknownFields(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.json")
	writeFile(t, path, `{"unknownPolicyField": true}`)

	_, err := aclpolicy.Load(path)
	if err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("Load error = %v, want unknown field", err)
	}
}

func TestWriteAndLoad(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.json")
	policy := &tailscale.ACL{
		Grants: []tailscale.Grant{{
			Source:      []string{"autogroup:member"},
			Destination: []string{"tag:web"},
			IP:          []string{"tcp:443"},
		}},
	}
	if err := aclpolicy.Write(path, policy); err != nil {
		t.Fatal(err)
	}
	got, err := aclpolicy.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Grants) != 1 || got.Grants[0].Destination[0] != "tag:web" {
		t.Fatalf("round trip Grants = %#v", got.Grants)
	}
}

func TestReadRawRejectsInvalidHuJSON(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.json")
	writeFile(t, path, `{"grants": [`)
	if _, err := aclpolicy.ReadRaw(path); err == nil {
		t.Fatal("ReadRaw accepted invalid HuJSON")
	}
}

func TestRepositoryPolicyUsesSupportedTailscaleTypes(t *testing.T) {
	t.Parallel()
	policy, err := aclpolicy.Load(filepath.Join("testdata", "acl.hujson"))
	if err != nil {
		t.Fatal(err)
	}
	if len(policy.Grants) == 0 || len(policy.NodeAttrs) == 0 || len(policy.SSH) == 0 {
		t.Fatalf("repository policy was incompletely decoded: %#v", policy)
	}
}

func TestEvaluateTestsGolden(t *testing.T) {
	t.Parallel()
	policy, err := aclpolicy.Load(filepath.Join("testdata", "tests_policy.hujson"))
	if err != nil {
		t.Fatal(err)
	}
	report, err := aclpolicy.EvaluateTests(policy, aclpolicy.TestOptions{})
	if err != nil {
		t.Fatal(err)
	}
	got, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')
	want, err := os.ReadFile(filepath.Join("testdata", "tests_report.golden.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("EvaluateTests report:\n%s\nwant:\n%s", got, want)
	}
}

func TestEvaluateReachabilityGolden(t *testing.T) {
	t.Parallel()
	policy, err := aclpolicy.Load(filepath.Join("testdata", "reachability_policy.hujson"))
	if err != nil {
		t.Fatal(err)
	}
	queries := []struct {
		source string
		target string
	}{
		{"alice@example.com", "tag:web:443"},
		{"alice@example.com", "tag:web:22"},
		{"alice@example.com", "web:8042"},
		{"alice@example.com", "10.20.16.0/20:8042"},
		{"tag:batch", "tag:db:5432"},
		{"10.1.0.0/16", "tag:metrics:9100"},
	}
	results := make([]aclpolicy.ReachabilityResult, 0, len(queries))
	for _, query := range queries {
		decision, evaluateErr := aclpolicy.EvaluateReachability(
			policy,
			query.source,
			query.target,
			aclpolicy.ReachabilityOptions{},
		)
		if evaluateErr != nil {
			t.Fatalf("EvaluateReachability(%q, %q): %v", query.source, query.target, evaluateErr)
		}
		results = append(results, decision)
	}
	got, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')
	want, err := os.ReadFile(filepath.Join("testdata", "reachability_report.golden.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("EvaluateReachability report:\n%s\nwant:\n%s", got, want)
	}
}

func TestEvaluateReachabilityUnsupportedRule(t *testing.T) {
	t.Parallel()
	policy := &tailscale.ACL{Grants: []tailscale.Grant{{
		Source:      []string{"alice@example.com"},
		Destination: []string{"tag:web"},
		IP:          []string{"tcp:443"},
		Via:         []string{"tag:router"},
	}}}
	_, err := aclpolicy.EvaluateReachability(
		policy,
		"alice@example.com",
		"tag:web:443",
		aclpolicy.ReachabilityOptions{},
	)
	if err == nil || !strings.Contains(err.Error(), "unsupported via routing") {
		t.Fatalf("error = %v, want unsupported via routing", err)
	}
}

func TestEvaluateReachabilityStrictRejectsMalformedRule(t *testing.T) {
	t.Parallel()
	for _, capability := range []string{"tcp:https", "65536", "80-70", "80,abc"} {
		t.Run(capability, func(t *testing.T) {
			t.Parallel()
			assertMalformedCapabilityHandling(t, capability)
		})
	}
}

func TestAutogroupInternetRequiresEntireCIDRToBePublic(t *testing.T) {
	t.Parallel()
	policy := &tailscale.ACL{Grants: []tailscale.Grant{{
		Source:      []string{"alice@example.com"},
		Destination: []string{"autogroup:internet"},
		IP:          []string{"tcp:443"},
	}}}
	testCases := []struct {
		destination string
		wantAllowed bool
	}{
		{"8.8.8.0/24:443", true},
		{"64.0.0.0/2:443", false},
		{"8.0.0.0/5:443", false},
		{"100.64.0.0/10:443", false},
		{"[2001:4860::/32]:443", true},
		{"[8000::/1]:443", false},
	}
	for _, testCase := range testCases {
		t.Run(testCase.destination, func(t *testing.T) {
			t.Parallel()
			decision, err := aclpolicy.EvaluateReachability(
				policy,
				"alice@example.com",
				testCase.destination,
				aclpolicy.ReachabilityOptions{},
			)
			if err != nil {
				t.Fatal(err)
			}
			if decision.Allowed != testCase.wantAllowed {
				t.Errorf("Allowed = %t, want %t (%#v)", decision.Allowed, testCase.wantAllowed, decision)
			}
		})
	}
}

func TestEvaluateReachabilityAcceptsTargetSyntax(t *testing.T) {
	t.Parallel()
	testCases := []struct {
		name            string
		value           string
		wantDestination string
		wantPort        uint16
	}{
		{"hostname", "web:443", "web", 443},
		{"tag", "tag:web:443", "tag:web", 443},
		{"IPv4 address", "100.64.0.1:22", "100.64.0.1", 22},
		{"bracketed IPv6 address", "[2001:db8::1]:443", "2001:db8::1", 443},
		{"bracketed IPv6 prefix", "[2001:db8::/32]:443", "2001:db8::/32", 443},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			decision, err := aclpolicy.EvaluateReachability(
				&tailscale.ACL{},
				"alice@example.com",
				testCase.value,
				aclpolicy.ReachabilityOptions{},
			)
			if err != nil {
				t.Fatal(err)
			}
			if decision.Destination != testCase.wantDestination || decision.Port != testCase.wantPort {
				t.Errorf(
					"destination = %q:%d, want %q:%d",
					decision.Destination,
					decision.Port,
					testCase.wantDestination,
					testCase.wantPort,
				)
			}
		})
	}
}

func TestEvaluateReachabilityRejectsInvalidTargetSyntax(t *testing.T) {
	t.Parallel()
	testCases := []struct {
		name      string
		value     string
		wantError string
	}{
		{"empty", "", "destination is empty"},
		{"missing port", "web", "must have host:port syntax"},
		{"bare IPv6 address", "2001:db8::1", "must use [ipv6]:port syntax"},
		{"missing IPv6 port", "[2001:db8::1]", "must use [ipv6]:port syntax"},
		{"malformed brackets", "web]:443", "has malformed brackets"},
		{"port out of range", "web:65536", "has invalid port"},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			_, err := aclpolicy.EvaluateReachability(
				&tailscale.ACL{},
				"alice@example.com",
				testCase.value,
				aclpolicy.ReachabilityOptions{},
			)
			if err == nil || !strings.Contains(err.Error(), testCase.wantError) {
				t.Fatalf("error = %v, want containing %q", err, testCase.wantError)
			}
		})
	}
}

func TestEvaluateReachabilityImplicitDefaultAllow(t *testing.T) {
	t.Parallel()
	decision, err := aclpolicy.EvaluateReachability(
		&tailscale.ACL{},
		"alice@example.com",
		"tag:web:443",
		aclpolicy.ReachabilityOptions{},
	)
	if err != nil {
		t.Fatal(err)
	}
	if !decision.Allowed || decision.Rule != nil ||
		!strings.Contains(decision.Evidence, "implicit default allow") {
		t.Errorf("decision = %#v, want implicit default allow", decision)
	}
}

func TestEvaluateTestsMissingSection(t *testing.T) {
	t.Parallel()
	report, err := aclpolicy.EvaluateTests(&tailscale.ACL{}, aclpolicy.TestOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if report.Summary != (aclpolicy.TestSummary{}) || report.Assertions == nil || len(report.Assertions) != 0 {
		t.Errorf("report = %#v, want an empty initialized report", report)
	}
}

func assertMalformedCapabilityHandling(t *testing.T, capability string) {
	t.Helper()
	policy := &tailscale.ACL{Grants: []tailscale.Grant{{
		Source:      []string{"alice@example.com"},
		Destination: []string{"tag:web"},
		IP:          []string{capability},
	}}}
	decision, err := aclpolicy.EvaluateReachability(
		policy,
		"alice@example.com",
		"tag:web:443",
		aclpolicy.ReachabilityOptions{},
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(decision.Skipped) != 1 ||
		decision.Skipped[0].Rule != "grants[0].ip[0]" ||
		decision.Skipped[0].Value != capability {
		t.Fatalf("Skipped = %#v, want malformed capability %q", decision.Skipped, capability)
	}
	if decision.Allowed ||
		!strings.Contains(strings.Join(decision.Trace, "\n"), "network capability could not be parsed") {
		t.Errorf("decision = %#v, want a denied verdict that identifies the parse failure", decision)
	}
	report, err := aclpolicy.EvaluateTests(policy, aclpolicy.TestOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Skipped) != 1 || report.Skipped[0].Value != capability {
		t.Errorf("test Skipped = %#v, want malformed capability %q", report.Skipped, capability)
	}

	_, err = aclpolicy.EvaluateReachability(
		policy,
		"alice@example.com",
		"tag:web:443",
		aclpolicy.ReachabilityOptions{Strict: true},
	)
	if err == nil || !strings.Contains(err.Error(), "grants[0].ip[0]") {
		t.Fatalf("reachability error = %v, want malformed grant location", err)
	}
	_, err = aclpolicy.EvaluateTests(policy, aclpolicy.TestOptions{Strict: true})
	if err == nil || !strings.Contains(err.Error(), "grants[0].ip[0]") {
		t.Fatalf("test error = %v, want malformed grant location", err)
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
