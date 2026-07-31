package aclpolicy_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
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
	testCases := []struct {
		name   string
		policy string
		field  string
	}{
		{"upstream field typo", `{"tagOwner": {}}`, "tagOwner"},
		{"local field typo", `{"sshTets": []}`, "sshTets"},
		{
			"nested local field typo",
			`{"ssh": [{"action": "accept", "src": ["*"], "dst": ["*"], "users": ["root"], "acceptEnvv": ["LANG"]}]}`,
			"acceptEnvv",
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "acl.json")
			writeFile(t, path, testCase.policy)

			_, err := aclpolicy.Load(path)
			if err == nil || !strings.Contains(err.Error(), `unknown field "`+testCase.field+`"`) {
				t.Fatalf("Load error = %v, want unknown field %q", err, testCase.field)
			}
		})
	}
}

func TestLoadPreservesSSHTests(t *testing.T) {
	t.Parallel()
	policy, err := aclpolicy.Load(filepath.Join("testdata", "sshtests_policy.hujson"))
	if err != nil {
		t.Fatal(err)
	}
	if len(policy.SSHTests) != 1 {
		t.Fatalf("SSHTests = %#v, want one assertion", policy.SSHTests)
	}
	got := policy.SSHTests[0]
	if got.Source != "alice@example.com" ||
		!reflect.DeepEqual(got.Destination, []string{"tag:ssh-only"}) ||
		!reflect.DeepEqual(got.Accept, []string{"ubuntu"}) ||
		!reflect.DeepEqual(got.Check, []string{"root"}) ||
		!reflect.DeepEqual(got.Deny, []string{"guest"}) {
		t.Errorf("SSHTests[0] = %#v", got)
	}
	wantAttrs := map[string]any{
		"node:os":              "linux",
		"custom:securityScore": float64(90),
	}
	if !reflect.DeepEqual(got.SrcPostureAttrs, wantAttrs) {
		t.Errorf("SSHTests[0].SrcPostureAttrs = %#v, want %#v", got.SrcPostureAttrs, wantAttrs)
	}
	if len(policy.SSH) != 1 || !reflect.DeepEqual(policy.SSH[0].AcceptEnv, []string{"LANG", "LC_*"}) {
		t.Errorf("SSH = %#v, want acceptEnv preserved", policy.SSH)
	}
}

func TestWritePreservesSSHTests(t *testing.T) {
	t.Parallel()
	policy, err := aclpolicy.Load(filepath.Join("testdata", "sshtests_policy.hujson"))
	if err != nil {
		t.Fatal(err)
	}
	beforeSSH, err := json.Marshal(policy.SSH)
	if err != nil {
		t.Fatal(err)
	}
	beforeTests, err := json.Marshal(policy.SSHTests)
	if err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(t.TempDir(), "acl.json")
	if err = aclpolicy.Write(path, policy); err != nil {
		t.Fatal(err)
	}
	after, err := aclpolicy.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	afterSSH, err := json.Marshal(after.SSH)
	if err != nil {
		t.Fatal(err)
	}
	afterTests, err := json.Marshal(after.SSHTests)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(afterSSH, beforeSSH) {
		t.Errorf("SSH changed across Load -> Write -> Load:\nbefore: %s\nafter:  %s", beforeSSH, afterSSH)
	}
	if !bytes.Equal(afterTests, beforeTests) {
		t.Errorf("SSHTests changed across Load -> Write -> Load:\nbefore: %s\nafter:  %s", beforeTests, afterTests)
	}
}

func TestLoadSyncsShadowedSSH(t *testing.T) {
	t.Parallel()
	policy, err := aclpolicy.Load(filepath.Join("testdata", "sshtests_policy.hujson"))
	if err != nil {
		t.Fatal(err)
	}
	if len(policy.ACL.SSH) != len(policy.SSH) {
		t.Fatalf("len(ACL.SSH) = %d, len(SSH) = %d", len(policy.ACL.SSH), len(policy.SSH))
	}
	for i := range policy.SSH {
		if !reflect.DeepEqual(policy.ACL.SSH[i], policy.SSH[i].ACLSSH) {
			t.Errorf("ACL.SSH[%d] = %#v, want %#v", i, policy.ACL.SSH[i], policy.SSH[i].ACLSSH)
		}
	}
}

// TestWriteRejectsSSHOnlyInMirror pins the one way this package could silently
// drop policy data. Policy.SSH shadows the embedded ACL.SSH, so a Policy whose
// rules live only in the mirror marshals to no "ssh" key at all. Nothing builds
// that state today; the guard exists so a future caller that copies Load's
// mirror assignment in reverse fails loudly instead of writing an empty policy.
func TestWriteRejectsSSHOnlyInMirror(t *testing.T) {
	t.Parallel()
	policy := &aclpolicy.Policy{
		ACL: tailscale.ACL{
			SSH: []tailscale.ACLSSH{{
				Action:      "accept",
				Source:      []string{"autogroup:member"},
				Destination: []string{"tag:web"},
				Users:       []string{"ubuntu"},
			}},
		},
	}
	path := filepath.Join(t.TempDir(), "acl.json")

	err := aclpolicy.Write(path, policy)
	if err == nil {
		t.Fatal("Write accepted a Policy whose ssh rules exist only in the ACL.SSH mirror")
	}
	if !strings.Contains(err.Error(), "ACL.SSH") {
		t.Errorf("Write error = %v, want it to name the shadowed mirror", err)
	}
	// The refusal must precede the write, so a rejected policy never lands on
	// disk half-encoded.
	if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
		t.Errorf("Write created %s despite rejecting the policy", path)
	}
}

func TestWriteAndLoad(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.json")
	policy := &aclpolicy.Policy{
		ACL: tailscale.ACL{
			Grants: []tailscale.Grant{{
				Source:      []string{"autogroup:member"},
				Destination: []string{"tag:web"},
				IP:          []string{"tcp:443"},
			}},
		},
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

func TestJSONPointerEscapesSegments(t *testing.T) {
	t.Parallel()
	got := aclpolicy.JSONPointer("tagOwners", "tag:ops/platform~blue")
	want := "/tagOwners/tag:ops~1platform~0blue"
	if got != want {
		t.Errorf("JSONPointer() = %q, want %q", got, want)
	}
}

// encoding/json resolves duplicate members last-wins and hujson resolves them
// first-wins. A policy carrying both would be validated through one member and
// patched through the other, so Load must refuse it outright.
func TestLoadRejectsDuplicateMembers(t *testing.T) {
	t.Parallel()
	testCases := map[string]string{
		"top level": `{
			"grants": [{"src": ["group:FIRST"], "dst": ["tag:b"], "ip": ["tcp:1"]}],
			"grants": [{"src": ["group:SECOND"], "dst": ["tag:b"], "ip": ["tcp:2"]}],
		}`,
		"nested":   `{"tagOwners": {"tag:web": ["group:a"], "tag:web": ["group:b"]}}`,
		"in array": `{"grants": [{"src": ["a"], "src": ["b"], "dst": ["tag:b"], "ip": ["tcp:1"]}]}`,
		"deep in ssh": `{"ssh": [{"action": "accept", "src": ["autogroup:member"],` +
			` "dst": ["autogroup:self"], "users": ["root"], "users": ["ubuntu"]}]}`,
	}
	for name, policy := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "acl.hujson")
			writeFile(t, path, policy)
			_, err := aclpolicy.Load(path)
			if err == nil {
				t.Fatal("Load accepted a policy with duplicate members")
			}
			if !strings.Contains(err.Error(), "duplicate object member") {
				t.Errorf("Load error = %v, want a duplicate-member complaint", err)
			}
		})
	}
}

// PatchAdd must encode a "value" member even for values that marshal to a JSON
// zero value; RFC 6902 requires it and hujson rejects an add without one.
func TestPatchAddAlwaysEncodesAValue(t *testing.T) {
	t.Parallel()
	testCases := map[string]any{
		"nil":          nil,
		"empty string": "",
		"empty slice":  []string{},
		"false":        false,
	}
	for name, value := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "acl.hujson")
			writeFile(t, path, "{\n\t// keep\n\t\"hosts\": {},\n}\n")
			if err := aclpolicy.WritePatch(path, aclpolicy.PatchAdd(value, "hosts", "probe")); err != nil {
				t.Fatalf("WritePatch(%v): %v", value, err)
			}
			got, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(got), `"probe"`) {
				t.Errorf("patch did not add the member:\n%s", got)
			}
		})
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
	if len(policy.SSHTests) == 0 || len(policy.SSH[0].AcceptEnv) == 0 {
		t.Fatalf("repository SSH extensions were incompletely decoded: %#v", policy)
	}
}

func TestEvaluateTestsGolden(t *testing.T) {
	t.Parallel()
	policy, err := aclpolicy.Load(filepath.Join("testdata", "tests_policy.hujson"))
	if err != nil {
		t.Fatal(err)
	}
	report, err := aclpolicy.EvaluateTests(&policy.ACL, aclpolicy.TestOptions{})
	if err != nil {
		t.Fatal(err)
	}
	assertGolden(t, "tests_report.golden.json", report)
}

func TestEvaluateUnprovenDenyGolden(t *testing.T) {
	t.Parallel()
	policy, err := aclpolicy.Load(filepath.Join("testdata", "unproven_deny_policy.hujson"))
	if err != nil {
		t.Fatal(err)
	}
	report, err := aclpolicy.EvaluateTests(&policy.ACL, aclpolicy.TestOptions{})
	if err != nil {
		t.Fatal(err)
	}
	assertGolden(t, "unproven_deny_report.golden.json", report)

	if len(report.Assertions) != 6 {
		t.Fatalf("assertions = %d, want 6", len(report.Assertions))
	}
	wantStatuses := []aclpolicy.AssertionStatus{
		aclpolicy.AssertionIndeterminate,
		aclpolicy.AssertionPass,
		aclpolicy.AssertionIndeterminate,
		aclpolicy.AssertionPass,
		aclpolicy.AssertionIndeterminate,
		aclpolicy.AssertionPass,
	}
	for index, want := range wantStatuses {
		if got := report.Assertions[index].Status; got != want {
			t.Errorf("assertions[%d].Status = %q, want %q", index, got, want)
		}
	}
	if len(report.Skipped) != 3 {
		t.Fatalf("skipped = %#v, want malformed grant port, protocol, and ACL destination", report.Skipped)
	}
	if report.Skipped[1].Rule != "grants[1].ip[0]" {
		t.Errorf("skipped = %#v, want the unknown protocol reported at grants[1].ip[0]", report.Skipped)
	}
}

func TestEvaluateUnprovenDenyStrictRejectsUnknownProtocol(t *testing.T) {
	t.Parallel()
	policy := &tailscale.ACL{Grants: []tailscale.Grant{{
		Source:      []string{"alice@example.com"},
		Destination: []string{"tag:web"},
		IP:          []string{"tpc:443"},
	}}}
	_, err := aclpolicy.EvaluateTests(policy, aclpolicy.TestOptions{Strict: true})
	if err == nil || !strings.Contains(err.Error(), "tpc:443") {
		t.Fatalf("error = %v, want strict mode to reject the unknown protocol", err)
	}
}

func TestEvaluateReachabilityGolden(t *testing.T) {
	t.Parallel()
	policy, err := aclpolicy.Load(filepath.Join("testdata", "reachability_policy.hujson"))
	if err != nil {
		t.Fatal(err)
	}
	queries := []struct {
		source   string
		target   string
		protocol aclpolicy.Protocol
	}{
		{source: "alice@example.com", target: "tag:web:443"},
		{source: "alice@example.com", target: "tag:web:22"},
		{source: "alice@example.com", target: "web:8042"},
		{source: "alice@example.com", target: "10.20.16.0/20:8042"},
		{source: "tag:batch", target: "tag:db:5432"},
		{source: "10.1.0.0/16", target: "tag:metrics:9100"},
		// The grant is udp-only, so narrowing to tcp must flip the verdict.
		{source: "tag:batch", target: "tag:db:5432", protocol: aclpolicy.ProtocolUDP},
		{source: "tag:batch", target: "tag:db:5432", protocol: aclpolicy.ProtocolTCP},
		// Gated on autogroup:admin — answerable only in the control plane.
		{source: "alice@example.com", target: "tag:audit:8443"},
		// Same grant, but the destination rules it out, so the answer is a
		// clean deny rather than indeterminate.
		{source: "alice@example.com", target: "tag:audit:9999"},
		// autogroup:tagged resolves from the query itself.
		{source: "tag:batch", target: "tag:log:514"},
		{source: "alice@example.com", target: "tag:log:514"},
	}
	results := make([]aclpolicy.ReachabilityResult, 0, len(queries))
	for _, query := range queries {
		decision, evaluateErr := aclpolicy.EvaluateReachability(
			&policy.ACL,
			query.source,
			query.target,
			aclpolicy.ReachabilityOptions{Protocol: query.protocol},
		)
		if evaluateErr != nil {
			t.Fatalf("EvaluateReachability(%q, %q): %v", query.source, query.target, evaluateErr)
		}
		results = append(results, decision)
	}
	assertGolden(t, "reachability_report.golden.json", results)
}

// A rule using via or srcPosture is no longer an error from check; see
// TestUnevaluatableGateIsIndeterminate in reachability_test.go, which asserts
// the third verdict that replaced it. EvaluateTests still errors, which
// TestEvaluateTestsStillErrorsOnUnevaluatableRule locks in.

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
			if (decision.Access == aclpolicy.AccessAllow) != testCase.wantAllowed {
				t.Errorf("Access = %q, want allowed=%t (%#v)", decision.Access, testCase.wantAllowed, decision)
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
	if decision.Access != aclpolicy.AccessAllow || decision.Rule != nil ||
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
	if decision.Access != aclpolicy.AccessIndeterminate ||
		!strings.Contains(strings.Join(decision.Trace, "\n"), "network capability could not be parsed") {
		t.Errorf("decision = %#v, want an indeterminate verdict that identifies the parse failure", decision)
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
