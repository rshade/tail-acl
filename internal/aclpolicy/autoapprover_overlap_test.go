package aclpolicy_test

import (
	"path/filepath"
	"slices"
	"strings"
	"testing"

	tailscale "tailscale.com/client/tailscale/v2"

	"github.com/rshade/tsacl/internal/aclpolicy"
)

func TestLintAutoApproverRouteOverlap(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name     string
		routes   map[string][]string
		wantRule string
		want     string
	}{
		{
			name:     "masked duplicate",
			routes:   map[string][]string{"10.0.0.1/8": {"group:eng"}, "10.0.0.0/8": {"group:eng"}},
			wantRule: "autoApprovers.routes[10.0.0.0/8], autoApprovers.routes[10.0.0.1/8]",
			want:     "mask to the same CIDR 10.0.0.0/8",
		},
		{
			name:     "partial overlap",
			routes:   map[string][]string{"10.0.0.0/24": {"group:eng"}, "10.0.0.128/25": {"group:eng"}},
			wantRule: "autoApprovers.routes[10.0.0.0/24], autoApprovers.routes[10.0.0.128/25]",
			want:     "overlap",
		},
		{
			name:   "disjoint",
			routes: map[string][]string{"10.0.0.0/24": {"group:eng"}, "10.1.0.0/24": {"group:eng"}},
		},
		{
			name: "via pair",
			routes: map[string][]string{
				"fd7a:115c:a1e0:b1a::/64":           {"group:eng"},
				"fd7a:115c:a1e0:b1a:0:2a:a00:0/104": {"group:eng"},
			},
		},
		{
			name: "via beside ipv4",
			routes: map[string][]string{
				"fd7a:115c:a1e0:b1a:0:2a:a00:0/104": {"group:eng"},
				"10.0.0.0/8":                        {"group:eng"},
			},
		},
		{
			name:   "unparsed key",
			routes: map[string][]string{"not-a-cidr": {"group:eng"}, "10.0.0.0/8": {"group:eng"}},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			assertRouteOverlap(t, test.routes, test.wantRule, test.want)
		})
	}
}

func assertRouteOverlap(t *testing.T, routes map[string][]string, wantRule, want string) {
	t.Helper()
	policy := &tailscale.ACL{AutoApprovers: &tailscale.ACLAutoApprovers{Routes: routes}}
	report, err := aclpolicy.EvaluateLint(policy, aclpolicy.LintOptions{})
	if err != nil {
		t.Fatal(err)
	}
	var matched []aclpolicy.LintFinding
	for _, finding := range report.Findings {
		if finding.ID == aclpolicy.LintAutoApproverRouteOverlap {
			matched = append(matched, finding)
		}
	}
	if want == "" {
		if len(matched) != 0 {
			t.Fatalf("findings = %#v", matched)
		}
		return
	}
	if len(matched) != 1 || matched[0].Severity != aclpolicy.LintWarn || matched[0].Rule != wantRule {
		t.Fatalf("findings = %#v", matched)
	}
	if !strings.Contains(matched[0].Evidence, want) {
		t.Fatalf("evidence = %q", matched[0].Evidence)
	}
}

func TestLintAutoApproverRouteOverlapLoadsSpellingFixture(t *testing.T) {
	t.Parallel()
	policy, err := aclpolicy.Load(filepath.Join("testdata", "autoapprover_route_overlap.hujson"))
	if err != nil {
		t.Fatal(err)
	}
	report, err := aclpolicy.EvaluatePolicyLint(policy, aclpolicy.LintOptions{})
	if err != nil {
		t.Fatal(err)
	}
	var matched int
	for _, finding := range report.Findings {
		if finding.ID != aclpolicy.LintAutoApproverRouteOverlap {
			continue
		}
		matched++
		if !strings.Contains(finding.Evidence, "10.0.0.0/8") || !strings.Contains(finding.Evidence, "10.0.0.1/8") {
			t.Fatalf("evidence = %q", finding.Evidence)
		}
	}
	if matched != 1 {
		t.Fatalf("overlap findings = %d, report = %#v", matched, report.Findings)
	}
}

func TestLintCatalogAdvertisesAutoApproverRouteOverlap(t *testing.T) {
	t.Parallel()
	index := slices.IndexFunc(aclpolicy.LintCatalog(), func(check aclpolicy.LintCheck) bool {
		return check.ID == aclpolicy.LintAutoApproverRouteOverlap
	})
	if index < 0 {
		t.Fatal("catalog missing autoapprover-route-overlap")
	}
	if got := aclpolicy.LintCatalog()[index].Severity; got != aclpolicy.LintWarn {
		t.Fatalf("severity = %s", got)
	}
}
