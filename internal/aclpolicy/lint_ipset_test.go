package aclpolicy_test

import (
	"slices"
	"testing"

	tailscale "tailscale.com/client/tailscale/v2"

	"github.com/rshade/tail-acl/internal/aclpolicy"
)

func TestEvaluateLintFlagsIPSetMixedOperations(t *testing.T) {
	t.Parallel()
	policy := &tailscale.ACL{
		Hosts: map[string]string{"gw": "10.9.0.1"},
		IPSets: map[string][]string{
			"ipset:base":     {"10.0.0.0/8"},
			"ipset:mixed":    {"ipset:base", "host:gw", "add 10.0.0.0/8", "remove 10.1.0.0/16"},
			"ipset:explicit": {"add ipset:base", "remove 10.1.0.0/16"},
			"ipset:implicit": {"ipset:base", "add 10.2.0.0/16"},
		},
		TagOwners: map[string][]string{"tag:web": {"autogroup:admin"}},
		Grants: []tailscale.Grant{{
			Source:      []string{"tag:web"},
			Destination: []string{"ipset:mixed", "ipset:explicit", "ipset:implicit"},
			IP:          []string{"tcp:80"},
		}},
	}
	report, err := aclpolicy.EvaluateLint(policy, aclpolicy.LintOptions{})
	if err != nil {
		t.Fatal(err)
	}
	mixed := findingsByID(report, aclpolicy.LintIPSetMixedOperations)
	if len(mixed) != 1 {
		t.Fatalf("ipset-mixed-operations findings = %#v, want exactly one", mixed)
	}
	finding := mixed[0]
	if finding.Severity != aclpolicy.LintError {
		t.Errorf("severity = %s, want error", finding.Severity)
	}
	if finding.Rule != "ipsets[ipset:mixed]" || finding.Value != "ipset:base" {
		t.Errorf("finding locator = %s value = %s; want ipsets[ipset:mixed] and ipset:base",
			finding.Rule, finding.Value)
	}
	if finding.Remediation != `write it as "add ipset:base"; every member must be an explicit add or remove` {
		t.Errorf("remediation = %q", finding.Remediation)
	}
	if report.Summary.Error != 1 {
		t.Errorf("summary = %#v, want one error", report.Summary)
	}
	if unused := findingsByID(report, aclpolicy.LintUnusedIPSet); len(unused) != 0 {
		t.Errorf("unused-ipset findings = %#v, want none for an ipset nested in another", unused)
	}
	if unused := findingsByID(report, aclpolicy.LintUnusedHost); len(unused) != 0 {
		t.Errorf("unused-host findings = %#v, want none for a host: member", unused)
	}
}

func TestLintCatalogAdvertisesIPSetMixedOperations(t *testing.T) {
	t.Parallel()
	index := slices.IndexFunc(aclpolicy.LintCatalog(), func(check aclpolicy.LintCheck) bool {
		return check.ID == aclpolicy.LintIPSetMixedOperations
	})
	if index < 0 {
		t.Fatal("ipset-mixed-operations is missing from the catalog")
	}
	if got := aclpolicy.LintCatalog()[index].Severity; got != aclpolicy.LintError {
		t.Errorf("catalog severity = %s, want error", got)
	}
}
