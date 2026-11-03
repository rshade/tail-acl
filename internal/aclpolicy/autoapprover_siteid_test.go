package aclpolicy_test

import (
	"net/netip"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	tailscale "tailscale.com/client/tailscale/v2"
	"tailscale.com/net/tsaddr"

	"github.com/rshade/tsacl/internal/aclpolicy"
)

func TestLintAutoApproverSiteIDCollision(t *testing.T) {
	t.Parallel()
	site42Subnet10 := mustViaRoute(t, 42, "10.0.0.0/24")
	site42Subnet11 := mustViaRoute(t, 42, "10.1.0.0/24")
	site7Subnet10 := mustViaRoute(t, 7, "10.0.0.0/24")
	sameSite := map[string][]string{
		site42Subnet10: {"group:eng"},
		site42Subnet11: {"group:eng"},
	}
	differentSites := map[string][]string{
		site42Subnet10: {"group:eng"},
		site7Subnet10:  {"group:eng"},
	}
	ordinary := map[string][]string{
		"10.0.0.0/8": {"group:eng"},
		"10.1.0.0/8": {"group:eng"},
	}
	for _, test := range []struct {
		name   string
		routes map[string][]string
		want   bool
	}{
		{name: "same site different subnets", routes: sameSite, want: true},
		{name: "different site ids", routes: differentSites},
		{name: "ordinary cidrs", routes: ordinary},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			assertSiteIDAdvice(t, test.routes, test.want)
		})
	}
}

func TestLintAutoApproverSiteIDCollisionLoadsFixture(t *testing.T) {
	t.Parallel()
	policy, err := aclpolicy.Load(filepath.Join("testdata", "autoapprover_siteid_collision.hujson"))
	if err != nil {
		t.Fatal(err)
	}
	report, err := aclpolicy.EvaluatePolicyLint(policy, aclpolicy.LintOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if report.CountAtLeast(aclpolicy.LintWarn) != 0 {
		t.Fatalf("warn-or-above findings = %#v", report.Findings)
	}
	var matched int
	for _, finding := range report.Findings {
		if finding.ID != aclpolicy.LintAutoApproverSiteIDCollision {
			continue
		}
		matched++
		if finding.Severity != aclpolicy.LintAdvice {
			t.Fatalf("severity = %s", finding.Severity)
		}
		for _, route := range []string{
			mustViaRoute(t, 42, "10.0.0.0/24"),
			mustViaRoute(t, 42, "10.1.0.0/24"),
		} {
			if !strings.Contains(finding.Rule, route) {
				t.Fatalf("rule = %q, missing %s", finding.Rule, route)
			}
		}
	}
	if matched != 1 {
		t.Fatalf("site-id findings = %d, report = %#v", matched, report.Findings)
	}
}

func TestLintCatalogAdvertisesAutoApproverSiteIDCollision(t *testing.T) {
	t.Parallel()
	index := slices.IndexFunc(aclpolicy.LintCatalog(), func(check aclpolicy.LintCheck) bool {
		return check.ID == aclpolicy.LintAutoApproverSiteIDCollision
	})
	if index < 0 {
		t.Fatal("catalog missing autoapprover-siteid-collision")
	}
	if got := aclpolicy.LintCatalog()[index].Severity; got != aclpolicy.LintAdvice {
		t.Fatalf("severity = %s", got)
	}
}

func mustViaRoute(t *testing.T, site uint32, cidr string) string {
	t.Helper()
	prefix, err := tsaddr.MapVia(site, netip.MustParsePrefix(cidr))
	if err != nil {
		t.Fatal(err)
	}
	return prefix.String()
}

func assertSiteIDAdvice(t *testing.T, routes map[string][]string, want bool) {
	t.Helper()
	policy := &tailscale.ACL{AutoApprovers: &tailscale.ACLAutoApprovers{Routes: routes}}
	report, err := aclpolicy.EvaluateLint(policy, aclpolicy.LintOptions{})
	if err != nil {
		t.Fatal(err)
	}
	var matched []aclpolicy.LintFinding
	for _, finding := range report.Findings {
		if finding.ID == aclpolicy.LintAutoApproverSiteIDCollision {
			matched = append(matched, finding)
		}
	}
	if !want {
		if len(matched) != 0 {
			t.Fatalf("findings = %#v", matched)
		}
		return
	}
	if len(matched) != 1 || matched[0].Severity != aclpolicy.LintAdvice {
		t.Fatalf("findings = %#v", matched)
	}
	if !strings.Contains(matched[0].Evidence, "confirm they are the same site") {
		t.Fatalf("evidence = %q", matched[0].Evidence)
	}
	if !strings.Contains(matched[0].Remediation, "confirm these routes are the same site") {
		t.Fatalf("remediation = %q", matched[0].Remediation)
	}
	if matched[0].Value != "42" {
		t.Fatalf("value = %q", matched[0].Value)
	}
}
