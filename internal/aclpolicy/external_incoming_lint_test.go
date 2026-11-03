package aclpolicy_test

import (
	"slices"
	"testing"

	tailscale "tailscale.com/client/tailscale/v2"

	"github.com/rshade/tsacl/internal/aclpolicy"
)

func TestLintIncomingDisabledWhenFlagOmitted(t *testing.T) {
	t.Parallel()
	report := lintGrantAgainst(t, tailscale.ExternalTailnet{ExternalID: "tn-123"}, "group://partner/eng", "tag:web")
	findings := findingsByID(report, aclpolicy.LintExternalTailnetIncomingDisabled)
	if len(findings) != 1 {
		t.Fatalf("findings = %#v, want one", findings)
	}
	got := findings[0]
	if got.Rule != "grants[0].src[0]" || got.Severity != aclpolicy.LintWarn {
		t.Errorf("finding = %#v", got)
	}
	if got.Value != "group://partner/eng" {
		t.Errorf("value = %q", got.Value)
	}
	if got.Evidence == "" || got.Remediation == "" {
		t.Errorf("finding = %#v, want evidence and remediation", got)
	}
}

func TestLintIncomingDisabledWhenFlagFalse(t *testing.T) {
	t.Parallel()
	declaration := tailscale.ExternalTailnet{ExternalID: "tn-123", AllowIncomingConnections: false}
	report := lintGrantAgainst(t, declaration, "autogroup:member", "tag://partner/device")
	findings := findingsByID(report, aclpolicy.LintExternalTailnetIncomingDisabled)
	if len(findings) != 1 || findings[0].Rule != "grants[0].dst[0]" {
		t.Fatalf("findings = %#v", findings)
	}
	if findings[0].Severity != aclpolicy.LintWarn {
		t.Errorf("severity = %s", findings[0].Severity)
	}
}

func TestLintIncomingEnabledIsClean(t *testing.T) {
	t.Parallel()
	declaration := tailscale.ExternalTailnet{ExternalID: "tn-123", AllowIncomingConnections: true}
	report := lintGrantAgainst(t, declaration, "group://partner/eng", "tag://partner/device")
	if findings := findingsByID(report, aclpolicy.LintExternalTailnetIncomingDisabled); len(findings) != 0 {
		t.Errorf("findings = %#v, want none", findings)
	}
}

func TestLintUnknownAliasIsNotIncomingDisabled(t *testing.T) {
	t.Parallel()
	policy := &tailscale.ACL{
		Grants: []tailscale.Grant{{
			Source:      []string{"group://missing/eng"},
			Destination: []string{"autogroup:self"},
			IP:          []string{"*"},
		}},
	}
	report, err := aclpolicy.EvaluateLint(policy, aclpolicy.LintOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if findings := findingsByID(report, aclpolicy.LintExternalTailnetIncomingDisabled); len(findings) != 0 {
		t.Errorf("incoming findings = %#v, want none", findings)
	}
	if findings := findingsByID(report, aclpolicy.LintExternalTailnetAliasUnknown); len(findings) != 1 {
		t.Errorf("alias findings = %#v, want one", findings)
	}
}

func TestLintCatalogAdvertisesIncomingDisabled(t *testing.T) {
	t.Parallel()
	index := slices.IndexFunc(aclpolicy.LintCatalog(), func(check aclpolicy.LintCheck) bool {
		return check.ID == aclpolicy.LintExternalTailnetIncomingDisabled
	})
	if index < 0 {
		t.Fatal("catalog missing external-tailnet-incoming-disabled")
	}
	if got := aclpolicy.LintCatalog()[index].Severity; got != aclpolicy.LintWarn {
		t.Errorf("severity = %s, want warn", got)
	}
}

func lintGrantAgainst(
	t *testing.T,
	declaration tailscale.ExternalTailnet,
	source, destination string,
) aclpolicy.LintReport {
	t.Helper()
	policy := &tailscale.ACL{
		TagOwners: map[string][]string{"tag:web": {"autogroup:admin"}},
		ExternalTailnets: map[string]tailscale.ExternalTailnet{
			"partner": declaration,
		},
		Grants: []tailscale.Grant{{
			Source:      []string{source},
			Destination: []string{destination},
			IP:          []string{"*"},
		}},
	}
	report, err := aclpolicy.EvaluateLint(policy, aclpolicy.LintOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return report
}
