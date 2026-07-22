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

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
