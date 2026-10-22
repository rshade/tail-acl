package aclpolicy_test

import (
	"slices"
	"testing"

	tailscale "tailscale.com/client/tailscale/v2"

	"github.com/rshade/tailscale-utils/tail-acl/internal/aclpolicy"
)

func TestLintUnknownExternalTailnetAlias(t *testing.T) {
	t.Parallel()
	policy := &tailscale.ACL{
		TagOwners: map[string][]string{"tag:web": {"autogroup:admin"}},
		Grants: []tailscale.Grant{{
			Source:      []string{"group://unknown-alias/eng"},
			Destination: []string{"tag:web"},
			IP:          []string{"*"},
		}},
	}
	report, err := aclpolicy.EvaluateLint(policy, aclpolicy.LintOptions{})
	if err != nil {
		t.Fatal(err)
	}
	findings := findingsByID(report, aclpolicy.LintExternalTailnetAliasUnknown)
	if len(findings) != 1 {
		t.Fatalf("findings = %#v, want one", findings)
	}
	if findings[0].Rule != "grants[0].src[0]" || findings[0].Severity != aclpolicy.LintError {
		t.Errorf("finding = %#v", findings[0])
	}
	if findings[0].Value != "group://unknown-alias/eng" {
		t.Errorf("value = %q", findings[0].Value)
	}
}

func TestLintDeclaredExternalTailnetAliasIsClean(t *testing.T) {
	t.Parallel()
	policy := &tailscale.ACL{
		ExternalTailnets: map[string]tailscale.ExternalTailnet{
			"partner": {ExternalID: "tn-123"},
		},
		Grants: []tailscale.Grant{{
			Source:      []string{"group://partner/eng"},
			Destination: []string{"tag://partner/device"},
			IP:          []string{"*"},
		}},
	}
	report, err := aclpolicy.EvaluateLint(policy, aclpolicy.LintOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if findings := findingsByID(report, aclpolicy.LintExternalTailnetAliasUnknown); len(findings) != 0 {
		t.Errorf("alias findings = %#v, want none", findings)
	}
	if findings := findingsByID(report, aclpolicy.LintUndefinedReference); len(findings) != 0 {
		t.Errorf("undefined-reference = %#v, want none", findings)
	}
	if findings := findingsByID(report, aclpolicy.LintDstTagNoOwner); len(findings) != 0 {
		t.Errorf("dst-tag-no-owner = %#v, want none", findings)
	}
}

func TestLintCrossTailnetTagIsNotAnUnownedLocalTag(t *testing.T) {
	t.Parallel()
	policy := &tailscale.ACL{
		Grants: []tailscale.Grant{{
			Source:      []string{"autogroup:member"},
			Destination: []string{"tag://unknown/device"},
			IP:          []string{"*"},
		}},
	}
	report, err := aclpolicy.EvaluateLint(policy, aclpolicy.LintOptions{})
	if err != nil {
		t.Fatal(err)
	}
	findings := findingsByID(report, aclpolicy.LintExternalTailnetAliasUnknown)
	if len(findings) != 1 || findings[0].Rule != "grants[0].dst[0]" {
		t.Fatalf("findings = %#v", findings)
	}
	if extra := findingsByID(report, aclpolicy.LintDstTagNoOwner); len(extra) != 0 {
		t.Errorf("dst-tag-no-owner = %#v, want none", extra)
	}
}

func TestLintACLDestinationKeepsCrossTailnetSelector(t *testing.T) {
	t.Parallel()
	policy := &tailscale.ACL{
		ACLs: []tailscale.ACLEntry{{
			Action:      "accept",
			Source:      []string{"autogroup:member"},
			Destination: []string{"group://missing/eng:443"},
		}},
	}
	report, err := aclpolicy.EvaluateLint(policy, aclpolicy.LintOptions{})
	if err != nil {
		t.Fatal(err)
	}
	findings := findingsByID(report, aclpolicy.LintExternalTailnetAliasUnknown)
	if len(findings) != 1 || findings[0].Rule != "acls[0].dst[0]" {
		t.Fatalf("findings = %#v", findings)
	}
	if findings[0].Value != "group://missing/eng:443" {
		t.Errorf("value = %q, want the selector before port stripping", findings[0].Value)
	}
}

func TestLintUnparsedExternalSelector(t *testing.T) {
	t.Parallel()
	policy := &tailscale.ACL{
		Grants: []tailscale.Grant{{
			Source:      []string{"group://partner"},
			Destination: []string{"autogroup:internet"},
			IP:          []string{"*"},
		}},
	}
	report, err := aclpolicy.EvaluateLint(policy, aclpolicy.LintOptions{})
	if err != nil {
		t.Fatal(err)
	}
	findings := findingsByID(report, aclpolicy.LintExternalTailnetAliasUnknown)
	if len(findings) != 1 || findings[0].Rule != "grants[0].src[0]" {
		t.Fatalf("findings = %#v", findings)
	}
	if extra := findingsByID(report, aclpolicy.LintUndefinedReference); len(extra) != 0 {
		t.Errorf("undefined-reference = %#v, want none", extra)
	}
}

func TestLintAutoApproverDeclaredExternalAlias(t *testing.T) {
	t.Parallel()
	policy := &tailscale.ACL{
		ExternalTailnets: map[string]tailscale.ExternalTailnet{
			"partner": {ExternalID: "tn-123"},
		},
		AutoApprovers: &tailscale.ACLAutoApprovers{
			ExitNode: []string{"group://partner/eng"},
		},
	}
	report, err := aclpolicy.EvaluateLint(policy, aclpolicy.LintOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if findings := findingsByID(report, aclpolicy.LintUndefinedReference); len(findings) != 0 {
		t.Errorf("undefined-reference = %#v, want none", findings)
	}
	if findings := findingsByID(report, aclpolicy.LintExternalTailnetAliasUnknown); len(findings) != 0 {
		t.Errorf("alias findings = %#v, want none", findings)
	}
}

func TestLintCatalogAdvertisesExternalTailnetAlias(t *testing.T) {
	t.Parallel()
	index := slices.IndexFunc(aclpolicy.LintCatalog(), func(check aclpolicy.LintCheck) bool {
		return check.ID == aclpolicy.LintExternalTailnetAliasUnknown
	})
	if index < 0 {
		t.Fatal("catalog missing external-tailnet-alias-unknown")
	}
	if got := aclpolicy.LintCatalog()[index].Severity; got != aclpolicy.LintError {
		t.Errorf("severity = %s, want error", got)
	}
}
