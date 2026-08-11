package aclpolicy_test

import (
	"strings"
	"testing"

	tailscale "tailscale.com/client/tailscale/v2"

	"github.com/rshade/tailscale-utils/tail-acl/internal/aclpolicy"
)

const (
	realSCIMSelector = "group:i am a group@example.com"
	localNameHalf    = "group:i am a group"
)

// TestEvaluateLintSCIMLocalGroupCollision uses the selector shape observed in
// a deployed policy. The pre-@ half can also name a local group, so the
// name-shape exemption must surface that collision without changing whether the
// configured SCIM policy exempts the full selector.
func TestEvaluateLintSCIMLocalGroupCollision(t *testing.T) {
	t.Parallel()

	for _, testCase := range []struct {
		name          string
		groups        map[string][]string
		opts          aclpolicy.LintOptions
		wantCollision int
		wantUndefined int
		wantSCIMRefs  int
	}{
		{
			name:          "default exemption reports local collision",
			groups:        map[string][]string{localNameHalf: {"alice@example.com"}},
			wantCollision: 1,
			wantSCIMRefs:  1,
		},
		{
			name:         "ordinary synced group remains exempt",
			wantSCIMRefs: 1,
		},
		{
			name:          "listed domain reports local collision",
			groups:        map[string][]string{localNameHalf: {"alice@example.com"}},
			opts:          aclpolicy.LintOptions{SCIMDomains: []string{"example.com"}},
			wantCollision: 1,
			wantSCIMRefs:  1,
		},
		{
			name:          "unlisted domain reports collision and undefined reference",
			groups:        map[string][]string{localNameHalf: {"alice@example.com"}},
			opts:          aclpolicy.LintOptions{SCIMDomains: []string{"other.example"}},
			wantCollision: 1,
			wantUndefined: 1,
		},
		{
			name:          "strict mode keeps existing undefined-reference behavior",
			groups:        map[string][]string{localNameHalf: {"alice@example.com"}},
			opts:          aclpolicy.LintOptions{StrictSCIMGroups: true},
			wantUndefined: 1,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			policy := &tailscale.ACL{
				Groups:    testCase.groups,
				TagOwners: map[string][]string{"tag:web": {"autogroup:admin"}},
				Grants: []tailscale.Grant{{
					Source:      []string{realSCIMSelector},
					Destination: []string{"tag:web"},
					IP:          []string{"tcp:443"},
				}},
			}

			report, err := aclpolicy.EvaluateLint(policy, testCase.opts)
			if err != nil {
				t.Fatal(err)
			}
			if got := scimCollisionCount(report, aclpolicy.LintSCIMGroupShadowsLocal); got != testCase.wantCollision {
				t.Errorf("scim-group-shadows-local findings = %d, want %d (%#v)",
					got, testCase.wantCollision, report.Findings)
			}
			if got := scimCollisionCount(report, aclpolicy.LintUndefinedReference); got != testCase.wantUndefined {
				t.Errorf("undefined-reference findings = %d, want %d (%#v)",
					got, testCase.wantUndefined, report.Findings)
			}
			if report.Summary.SCIMGroupRefs != testCase.wantSCIMRefs {
				t.Errorf("Summary.SCIMGroupRefs = %d, want %d", report.Summary.SCIMGroupRefs, testCase.wantSCIMRefs)
			}
		})
	}
}

// TestSCIMLocalGroupCollisionFindingExplainsBothNames locks the evidence a
// human or agent needs to distinguish a synced group from a stale local-group
// reference. The trace must carry the local fact that made the warning fire.
func TestSCIMLocalGroupCollisionFindingExplainsBothNames(t *testing.T) {
	t.Parallel()
	policy := &tailscale.ACL{
		Groups:    map[string][]string{localNameHalf: {"alice@example.com"}},
		TagOwners: map[string][]string{"tag:web": {"autogroup:admin"}},
		Grants: []tailscale.Grant{{
			Source:      []string{realSCIMSelector},
			Destination: []string{"tag:web"},
			IP:          []string{"tcp:443"},
		}},
	}

	report, err := aclpolicy.EvaluateLint(policy, aclpolicy.LintOptions{})
	if err != nil {
		t.Fatal(err)
	}
	findings := scimCollisionFindings(report, aclpolicy.LintSCIMGroupShadowsLocal)
	if len(findings) != 1 {
		t.Fatalf("findings = %#v, want exactly one scim-group-shadows-local", report.Findings)
	}
	finding := findings[0]
	if finding.Severity != aclpolicy.LintWarn {
		t.Errorf("severity = %q, want warn", finding.Severity)
	}
	if finding.Rule != "grants[0].src[0]" {
		t.Errorf("rule = %q, want grants[0].src[0]", finding.Rule)
	}
	for field, text := range map[string]string{
		"evidence selector":    finding.Evidence,
		"evidence local group": finding.Evidence,
		"remediation selector": finding.Remediation,
		"remediation local":    finding.Remediation,
	} {
		want := realSCIMSelector
		if strings.Contains(field, "local") {
			want = localNameHalf
		}
		if !strings.Contains(text, want) {
			t.Errorf("%s = %q, want it to name %q", field, text, want)
		}
	}
	if !sliceContainsSubstring(finding.Trace, localNameHalf) {
		t.Errorf("trace = %#v, want the decisive local group %q", finding.Trace, localNameHalf)
	}
}

func scimCollisionCount(report aclpolicy.LintReport, id string) int {
	return len(scimCollisionFindings(report, id))
}

func scimCollisionFindings(report aclpolicy.LintReport, id string) []aclpolicy.LintFinding {
	findings := make([]aclpolicy.LintFinding, 0)
	for _, finding := range report.Findings {
		if finding.ID == id {
			findings = append(findings, finding)
		}
	}
	return findings
}

func sliceContainsSubstring(values []string, want string) bool {
	for _, value := range values {
		if strings.Contains(value, want) {
			return true
		}
	}
	return false
}
