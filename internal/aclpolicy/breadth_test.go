package aclpolicy_test

import (
	"encoding/json"
	"path/filepath"
	"testing"

	tailscale "tailscale.com/client/tailscale/v2"

	"github.com/rshade/tsacl/internal/aclpolicy"
)

func TestEvaluateLintBroadGolden(t *testing.T) {
	t.Parallel()
	policy, err := aclpolicy.Load(filepath.Join("testdata", "lint_broad_policy.hujson"))
	if err != nil {
		t.Fatal(err)
	}
	report, err := aclpolicy.EvaluatePolicyLint(policy, aclpolicy.LintOptions{})
	if err != nil {
		t.Fatal(err)
	}
	assertGolden(t, "lint_broad_report.golden.json", report)
}

func TestEvaluateLintBroadUntestedPredicate(t *testing.T) {
	t.Parallel()
	testCases := []struct {
		name  string
		grant tailscale.Grant
		want  int
	}{
		{"member all ports", grant([]string{"autogroup:member"}, []string{"tag:db"}, []string{"*"}), 1},
		{"members tcp all ports", grant([]string{"autogroup:members"}, []string{"tag:db"}, []string{"tcp:*"}), 1},
		{"tagged udp all ports", grant([]string{"autogroup:tagged"}, []string{"tag:db"}, []string{"udp:1-65535"}), 1},
		{"wildcard all ports", grant([]string{"*"}, []string{"tag:db"}, []string{"1-65535"}), 1},
		{"two concrete destinations", grant([]string{"autogroup:member"}, []string{"tag:db", "db"}, []string{"*"}), 2},
		{"narrow source", grant([]string{"group:dev"}, []string{"tag:db"}, []string{"*"}), 0},
		{"wildcard destination", grant([]string{"autogroup:member"}, []string{"*"}, []string{"*"}), 0},
		{"blanket destination", grant([]string{"autogroup:member"}, []string{"autogroup:tagged"}, []string{"*"}), 0},
		{"internet destination", grant([]string{"autogroup:member"}, []string{"autogroup:internet"}, []string{"*"}), 0},
		{"self destination", grant([]string{"autogroup:member"}, []string{"autogroup:self"}, []string{"*"}), 0},
		{"not every port", grant([]string{"autogroup:member"}, []string{"tag:db"}, []string{"tcp:1-65534"}), 0},
		{
			"whitespace around every port",
			grant([]string{"autogroup:member"}, []string{"tag:db"}, []string{"tcp: *"}),
			1,
		},
		{"src posture gate", func() tailscale.Grant {
			g := grant([]string{"autogroup:member"}, []string{"tag:db"}, []string{"*"})
			g.SrcPosture = []string{"posture:secure"}
			return g
		}(), 0},
		{"via gate", func() tailscale.Grant {
			g := grant([]string{"autogroup:member"}, []string{"tag:db"}, []string{"*"})
			g.Via = []string{"tag:router"}
			return g
		}(), 0},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			policy := broadPolicy(testCase.grant)
			report, err := aclpolicy.EvaluateLint(policy, aclpolicy.LintOptions{})
			if err != nil {
				t.Fatal(err)
			}
			if got := countByID(report, aclpolicy.LintBroadRuleUntested); got != testCase.want {
				t.Errorf("broad-rule-untested findings = %d, want %d: %#v", got, testCase.want, report.Findings)
			}
		})
	}
}

func TestEvaluateLintBroadUntestedCoverageIsPortInsensitive(t *testing.T) {
	t.Parallel()
	policy := broadPolicy(grant([]string{"autogroup:member"}, []string{"tag:db"}, []string{"*"}))
	policy.Tests = []tailscale.ACLTest{{Source: "somebody@example.com", Deny: []string{"tag:db:22"}}}
	report, err := aclpolicy.EvaluateLint(policy, aclpolicy.LintOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if got := countByID(report, aclpolicy.LintBroadRuleUntested); got != 0 {
		t.Errorf("findings = %#v, deny on the same host should cover every port", report.Findings)
	}
}

func TestEvaluateLintBroadUntestedAcceptTestIsNotCoverage(t *testing.T) {
	t.Parallel()
	policy := broadPolicy(grant([]string{"autogroup:member"}, []string{"tag:db"}, []string{"*"}))
	policy.Tests = []tailscale.ACLTest{{Source: "somebody@example.com", Accept: []string{"tag:db:5432"}}}
	report, err := aclpolicy.EvaluateLint(policy, aclpolicy.LintOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if got := countByID(report, aclpolicy.LintBroadRuleUntested); got != 1 {
		t.Errorf("broad-rule-untested findings = %d, want 1", got)
	}
}

func TestEvaluateLintBroadUntestedExclusion(t *testing.T) {
	t.Parallel()
	policy := broadPolicy(grant([]string{"autogroup:member"}, []string{"tag:db"}, []string{"*"}))
	for _, testCase := range []struct {
		name  string
		allow []string
		want  int
	}{
		{"matching", []string{" tag:db "}, 0},
		{"unrelated", []string{"tag:printer"}, 1},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			report, err := aclpolicy.EvaluateLint(policy, aclpolicy.LintOptions{AllowBroadDestinations: testCase.allow})
			if err != nil {
				t.Fatal(err)
			}
			if got := countByID(report, aclpolicy.LintBroadRuleUntested); got != testCase.want {
				t.Errorf("broad-rule-untested findings = %d, want %d", got, testCase.want)
			}
		})
	}
}

func TestEvaluateLintSuggestionIsFalsifiable(t *testing.T) {
	t.Parallel()
	policy := broadPolicy(grant([]string{"autogroup:member"}, []string{"tag:db"}, []string{"*"}))
	policy.Grants = append(policy.Grants, grant([]string{"group:dev"}, []string{"tag:db"}, []string{"tcp:5432"}))
	report, err := aclpolicy.EvaluateLint(policy, aclpolicy.LintOptions{})
	if err != nil {
		t.Fatal(err)
	}
	findings := findingsByID(report, aclpolicy.LintBroadRuleUntested)
	if len(findings) != 1 || findings[0].Suggestion == "" {
		t.Fatalf("findings = %#v, want one suggestion", findings)
	}
	if want := `{"src":"alice@example.com","deny":["tag:db:5432"]}`; findings[0].Suggestion != want {
		t.Errorf("Suggestion = %q, want %q", findings[0].Suggestion, want)
	}
	var suggestion tailscale.ACLTest
	if err = json.Unmarshal([]byte(findings[0].Suggestion), &suggestion); err != nil {
		t.Fatal(err)
	}
	policy.Tests = append(policy.Tests, suggestion)
	testReport, err := aclpolicy.EvaluateTests(policy, aclpolicy.TestOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if testReport.Summary.Total != 1 || testReport.Summary.Failed != 1 ||
		testReport.Assertions[0].Status != aclpolicy.AssertionFail {
		t.Errorf("test report = %#v, want exactly one failed assertion", testReport)
	}
}

func TestEvaluateLintSuggestionOmissions(t *testing.T) {
	t.Parallel()
	for _, testCase := range []struct {
		name   string
		source string
	}{
		{"no derived port", "autogroup:member"},
		{"wildcard source", "*"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			policy := broadPolicy(grant([]string{testCase.source}, []string{"tag:db"}, []string{"*"}))
			if testCase.source == "*" {
				portGrant := grant([]string{"group:dev"}, []string{"tag:db"}, []string{"tcp:5432"})
				policy.Grants = append(policy.Grants, portGrant)
			}
			report, err := aclpolicy.EvaluateLint(policy, aclpolicy.LintOptions{})
			if err != nil {
				t.Fatal(err)
			}
			findings := findingsByID(report, aclpolicy.LintBroadRuleUntested)
			if len(findings) != 1 || findings[0].Suggestion != "" {
				t.Errorf("findings = %#v, want one advisory without a suggestion", findings)
			}
		})
	}
}

func TestEvaluateLintSuggestionOmittedWhenNoConcreteSourceIsDerivable(t *testing.T) {
	t.Parallel()
	policy := broadPolicy(grant([]string{"autogroup:member"}, []string{"tag:db"}, []string{"*"}))
	policy.Groups = nil
	policy.Grants = append(policy.Grants, grant([]string{"group:dev"}, []string{"tag:db"}, []string{"tcp:5432"}))
	report, err := aclpolicy.EvaluateLint(policy, aclpolicy.LintOptions{})
	if err != nil {
		t.Fatal(err)
	}
	findings := findingsByID(report, aclpolicy.LintBroadRuleUntested)
	if len(findings) != 1 || findings[0].Suggestion != "" {
		t.Errorf("findings = %#v, want one advisory without a suggestion", findings)
	}
}

func TestEvaluateLintSuggestionUsesLowestAssociatedPort(t *testing.T) {
	t.Parallel()
	policy := broadPolicy(grant([]string{"autogroup:member"}, []string{"tag:db"}, []string{"*"}))
	policy.Grants = append(policy.Grants, grant([]string{"group:dev"}, []string{"tag:db"}, []string{"tcp:9000"}))
	policy.ACLs = []tailscale.ACLEntry{{
		Action:      "accept",
		Source:      []string{"group:dev"},
		Destination: []string{"tag:db:8000-8100"},
	}}
	policy.Tests = []tailscale.ACLTest{{Source: "alice@example.com", Accept: []string{"tag:db:7000"}}}
	report, err := aclpolicy.EvaluateLint(policy, aclpolicy.LintOptions{})
	if err != nil {
		t.Fatal(err)
	}
	findings := findingsByID(report, aclpolicy.LintBroadRuleUntested)
	want := `{"src":"alice@example.com","deny":["tag:db:7000"]}`
	if len(findings) != 1 || !json.Valid([]byte(findings[0].Suggestion)) ||
		findings[0].Suggestion != want {
		t.Errorf("findings = %#v, want suggestion using port 7000", findings)
	}
}

func TestEvaluateLintSuggestionBracketsIPv6(t *testing.T) {
	t.Parallel()
	policy := broadPolicy(grant([]string{"autogroup:member"}, []string{"2001:db8::1"}, []string{"*"}))
	policy.Grants = append(policy.Grants, grant([]string{"group:dev"}, []string{"2001:db8::1"}, []string{"tcp:443"}))
	report, err := aclpolicy.EvaluateLint(policy, aclpolicy.LintOptions{})
	if err != nil {
		t.Fatal(err)
	}
	findings := findingsByID(report, aclpolicy.LintBroadRuleUntested)
	if len(findings) != 1 || findings[0].Suggestion != `{"src":"alice@example.com","deny":["[2001:db8::1]:443"]}` {
		t.Errorf("findings = %#v, want a bracketed IPv6 suggestion", findings)
	}
}

func TestEvaluateLintSuggestionUsesLexicographicallySmallestBlanketSource(t *testing.T) {
	t.Parallel()
	policy := broadPolicy(grant(
		[]string{"autogroup:tagged", "autogroup:member"},
		[]string{"tag:db"},
		[]string{"*"},
	))
	policy.Grants = append(policy.Grants, grant([]string{"group:dev"}, []string{"tag:db"}, []string{"tcp:5432"}))
	report, err := aclpolicy.EvaluateLint(policy, aclpolicy.LintOptions{})
	if err != nil {
		t.Fatal(err)
	}
	findings := findingsByID(report, aclpolicy.LintBroadRuleUntested)
	want := `{"src":"alice@example.com","deny":["tag:db:5432"]}`
	if len(findings) != 1 || findings[0].Suggestion != want {
		t.Errorf("findings = %#v, want lexicographically stable source", findings)
	}
}

func TestEvaluateLintSuggestionPrefersTestableBlanketSource(t *testing.T) {
	t.Parallel()
	policy := broadPolicy(grant(
		[]string{"*", "autogroup:member"},
		[]string{"tag:db"},
		[]string{"*"},
	))
	policy.Grants = append(policy.Grants, grant([]string{"group:dev"}, []string{"tag:db"}, []string{"tcp:5432"}))
	report, err := aclpolicy.EvaluateLint(policy, aclpolicy.LintOptions{})
	if err != nil {
		t.Fatal(err)
	}
	findings := findingsByID(report, aclpolicy.LintBroadRuleUntested)
	want := `{"src":"alice@example.com","deny":["tag:db:5432"]}`
	if len(findings) != 1 || findings[0].Suggestion != want {
		t.Errorf("findings = %#v, want suggestion using testable blanket source", findings)
	}
}

func TestEvaluateLintSuggestionUsesLexicographicallySmallestDerivedSource(t *testing.T) {
	t.Parallel()
	policy := broadPolicy(grant([]string{"autogroup:member"}, []string{"tag:db"}, []string{"*"}))
	policy.Groups["group:dev"] = []string{"bob@example.com", "alice@example.com"}
	policy.Grants = append(policy.Grants, grant([]string{"group:dev"}, []string{"tag:db"}, []string{"tcp:5432"}))
	report, err := aclpolicy.EvaluateLint(policy, aclpolicy.LintOptions{})
	if err != nil {
		t.Fatal(err)
	}
	findings := findingsByID(report, aclpolicy.LintBroadRuleUntested)
	want := `{"src":"alice@example.com","deny":["tag:db:5432"]}`
	if len(findings) != 1 || findings[0].Suggestion != want {
		t.Errorf("findings = %#v, want lexicographically smallest concrete source", findings)
	}
}

func TestEvaluateLintSuggestionDerivesTaggedSource(t *testing.T) {
	t.Parallel()
	policy := broadPolicy(grant([]string{"autogroup:tagged"}, []string{"tag:db"}, []string{"*"}))
	policy.TagOwners["tag:app"] = []string{"group:dev"}
	policy.Grants = append(policy.Grants, grant([]string{"tag:app"}, []string{"tag:db"}, []string{"tcp:5432"}))
	report, err := aclpolicy.EvaluateLint(policy, aclpolicy.LintOptions{})
	if err != nil {
		t.Fatal(err)
	}
	findings := findingsByID(report, aclpolicy.LintBroadRuleUntested)
	want := `{"src":"tag:app","deny":["tag:db:5432"]}`
	if len(findings) != 1 || findings[0].Suggestion != want {
		t.Errorf("findings = %#v, want concrete tagged source", findings)
	}
}

func TestEvaluateLintBroadUntestedIgnoresLegacyACLs(t *testing.T) {
	t.Parallel()
	policy := broadPolicy()
	policy.ACLs = []tailscale.ACLEntry{{Action: "accept", Source: []string{"*"}, Destination: []string{"tag:db:*"}}}
	report, err := aclpolicy.EvaluateLint(policy, aclpolicy.LintOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if got := countByID(report, aclpolicy.LintBroadRuleUntested); got != 0 {
		t.Errorf("broad-rule-untested findings = %d, want 0 for legacy ACL", got)
	}
}

// TestEvaluateLintBroadUntestedTreatsDangerAllAsBlanketSource guards the
// widest selector in the language. policycore resolves autogroup:danger-all
// with matchesAlways, so a grant using it as a source is strictly broader than
// one using "*" and must not be quieter than one.
func TestEvaluateLintBroadUntestedTreatsDangerAllAsBlanketSource(t *testing.T) {
	t.Parallel()
	policy := broadPolicy(grant([]string{"autogroup:danger-all"}, []string{"tag:db"}, []string{"*"}))
	report, err := aclpolicy.EvaluateLint(policy, aclpolicy.LintOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if got := countByID(report, aclpolicy.LintBroadRuleUntested); got != 1 {
		t.Errorf("broad-rule-untested findings = %d, want 1: %#v", got, report.Findings)
	}
}

// TestEvaluateLintNoAutogroupIsAConcreteDestination locks the destination side
// of the same boundary: no autogroup is specific enough to write a targeted
// deny against, so none may be reported as a concrete destination. Role
// autogroups belong to tailnet-audit's grant-dst-widespread, which can consult
// the live roster this tool deliberately cannot.
func TestEvaluateLintNoAutogroupIsAConcreteDestination(t *testing.T) {
	t.Parallel()
	for _, destination := range []string{
		"autogroup:danger-all", "autogroup:shared", "autogroup:nonroot",
		"autogroup:admin", "autogroup:owner", "autogroup:internet", "autogroup:self",
	} {
		t.Run(destination, func(t *testing.T) {
			t.Parallel()
			policy := broadPolicy(grant([]string{"autogroup:member"}, []string{destination}, []string{"*"}))
			report, err := aclpolicy.EvaluateLint(policy, aclpolicy.LintOptions{})
			if err != nil {
				t.Fatal(err)
			}
			if got := countByID(report, aclpolicy.LintBroadRuleUntested); got != 0 {
				t.Errorf("broad-rule-untested findings = %d, want 0: %#v", got, report.Findings)
			}
		})
	}
}

// TestEvaluateLintSuggestionIsNeverSelfReferential guards against suggesting a
// deny assertion whose source equals its destination. Intra-tag traffic
// (database peers, replication) legitimately contradicts such an assertion, so
// the advisory omits the suggestion rather than pasting a degenerate one.
func TestEvaluateLintSuggestionIsNeverSelfReferential(t *testing.T) {
	t.Parallel()
	policy := &tailscale.ACL{
		TagOwners: map[string][]string{"tag:db": {"autogroup:admin"}},
		Grants: []tailscale.Grant{
			grant([]string{"autogroup:tagged"}, []string{"tag:db"}, []string{"*"}),
			grant([]string{"tag:db"}, []string{"tag:db"}, []string{"tcp:5432"}),
		},
	}
	report, err := aclpolicy.EvaluateLint(policy, aclpolicy.LintOptions{})
	if err != nil {
		t.Fatal(err)
	}
	findings := findingsByID(report, aclpolicy.LintBroadRuleUntested)
	if len(findings) != 1 {
		t.Fatalf("findings = %#v, want exactly one advisory", findings)
	}
	if findings[0].Suggestion != "" {
		t.Errorf("Suggestion = %q, want omitted rather than self-referential", findings[0].Suggestion)
	}
}

// TestEvaluateLintPortlessDenyIsNotCoverage pins that a deny entry with no port
// contributes no coverage key. destinationHost would split "tag:db" on its last
// colon into the garbage host "tag"; splitSelectorPort rejects it instead.
func TestEvaluateLintPortlessDenyIsNotCoverage(t *testing.T) {
	t.Parallel()
	policy := broadPolicy(grant([]string{"autogroup:member"}, []string{"tag:db"}, []string{"*"}))
	policy.Tests = []tailscale.ACLTest{{Source: "alice@example.com", Deny: []string{"tag:db"}}}
	report, err := aclpolicy.EvaluateLint(policy, aclpolicy.LintOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if got := countByID(report, aclpolicy.LintBroadRuleUntested); got != 1 {
		t.Errorf("findings = %d, want 1: a portless deny is not a readable assertion", got)
	}
}

// TestEvaluateLintBroadUntestedAllPortSpellings guards against reading the port
// spec as text. A false negative here means an all-port grant this advisory
// exists to find passes unreported, so every spelling the control plane accepts
// for "every port" must be recognized.
func TestEvaluateLintBroadUntestedAllPortSpellings(t *testing.T) {
	t.Parallel()
	for _, testCase := range []struct {
		capability string
		want       int
	}{
		{"*", 1},
		{"tcp:*", 1},
		{"1-65535", 1},
		{"tcp:1-65535", 1},
		{"tcp:0-65535", 1},
		{"tcp:1-1000,1001-65535", 1},
		{"tcp:5432", 0},
		{"tcp:1-65534", 0},
	} {
		t.Run(testCase.capability, func(t *testing.T) {
			t.Parallel()
			policy := broadPolicy(
				grant([]string{"autogroup:member"}, []string{"tag:db"}, []string{testCase.capability}),
			)
			report, err := aclpolicy.EvaluateLint(policy, aclpolicy.LintOptions{})
			if err != nil {
				t.Fatal(err)
			}
			if got := countByID(report, aclpolicy.LintBroadRuleUntested); got != testCase.want {
				t.Errorf("findings for ip %q = %d, want %d", testCase.capability, got, testCase.want)
			}
		})
	}
}

func grant(source, destination, ip []string) tailscale.Grant {
	return tailscale.Grant{Source: source, Destination: destination, IP: ip}
}

func broadPolicy(grants ...tailscale.Grant) *tailscale.ACL {
	return &tailscale.ACL{
		Groups:    map[string][]string{"group:dev": {"alice@example.com"}},
		Hosts:     map[string]string{"db": "100.64.0.10"},
		TagOwners: map[string][]string{"tag:db": {"group:dev"}},
		Grants:    grants,
	}
}
