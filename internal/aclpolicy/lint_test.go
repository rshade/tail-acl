package aclpolicy_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	tailscale "tailscale.com/client/tailscale/v2"

	"github.com/rshade/tailscale-utils/tail-acl/internal/aclpolicy"
)

func TestEvaluateLintGolden(t *testing.T) {
	t.Parallel()
	policy, err := aclpolicy.Load(filepath.Join("testdata", "lint_policy.hujson"))
	if err != nil {
		t.Fatal(err)
	}
	report, err := aclpolicy.EvaluateLint(policy, aclpolicy.LintOptions{})
	if err != nil {
		t.Fatal(err)
	}
	got, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')
	want, err := os.ReadFile(filepath.Join("testdata", "lint_report.golden.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("EvaluateLint report:\n%s\nwant:\n%s", got, want)
	}
}

func TestEvaluateLintCleanPolicyHasNoFindings(t *testing.T) {
	t.Parallel()
	policy := &tailscale.ACL{
		Groups:    map[string][]string{"group:dev": {"alice@example.com"}},
		TagOwners: map[string][]string{"tag:web": {"group:dev"}},
		Grants: []tailscale.Grant{
			{Source: []string{"group:dev"}, Destination: []string{"tag:web:443"}, IP: []string{"tcp:443"}},
		},
	}
	report, err := aclpolicy.EvaluateLint(policy, aclpolicy.LintOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if report.Summary.Total != 0 {
		t.Errorf("findings = %#v, want none", report.Findings)
	}
}

func TestEvaluateLintWildcardModes(t *testing.T) {
	t.Parallel()
	// Three grants: src-only *, dst-only *, and any-to-any.
	policy := &tailscale.ACL{
		TagOwners: map[string][]string{"tag:web": {"group:dev"}},
		Groups:    map[string][]string{"group:dev": {"alice@example.com"}},
		Grants: []tailscale.Grant{
			{Source: []string{"*"}, Destination: []string{"tag:web:443"}, IP: []string{"tcp:443"}},
			{Source: []string{"group:dev"}, Destination: []string{"*:443"}, IP: []string{"tcp:443"}},
			{Source: []string{"*"}, Destination: []string{"*:443"}, IP: []string{"tcp:443"}},
		},
	}
	for _, tc := range []struct {
		mode aclpolicy.WildcardPolicy
		want int
	}{
		{aclpolicy.WildcardAnyToAny, 1}, // only the any-to-any grant
		{aclpolicy.WildcardAny, 4},      // src, dst, then src+dst
		{aclpolicy.WildcardOff, 0},
	} {
		t.Run(string(tc.mode), func(t *testing.T) {
			t.Parallel()
			report, err := aclpolicy.EvaluateLint(policy, aclpolicy.LintOptions{Wildcard: tc.mode})
			if err != nil {
				t.Fatal(err)
			}
			if got := countByID(report, aclpolicy.LintOverbroadWildcard); got != tc.want {
				t.Errorf("overbroad-wildcard findings = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestEvaluateLintReferenceClassification(t *testing.T) {
	t.Parallel()
	// Autogroups (including ones policycore does not match), users, literal
	// addresses, and prefixes must all resolve; missing named selectors must not.
	policy := &tailscale.ACL{
		Groups:    map[string][]string{"group:known": {"alice@example.com"}},
		Hosts:     map[string]string{"known-host": "100.64.0.9"},
		IPSets:    map[string][]string{"ipset:known": {"10.0.0.0/8"}},
		TagOwners: map[string][]string{"tag:known": {"group:known"}},
	}
	for _, tc := range []struct {
		name       string
		source     string
		wantErrors int
	}{
		{"wildcard", "*", 0},
		{"autogroup member", "autogroup:member", 0},
		{"unknown autogroup is not flagged", "autogroup:nonroot", 0},
		{"user", "alice@example.com", 0},
		{"literal ipv4", "100.64.0.1", 0},
		{"literal cidr", "10.0.0.0/8", 0},
		{"known group", "group:known", 0},
		{"known host", "known-host", 0},
		{"known ipset", "ipset:known", 0},
		{"missing group", "group:ghost", 1},
		{"missing ipset", "ipset:ghost", 1},
		{"src tag without owner", "tag:ghost", 1},
		{"unknown host alias", "mystery", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p := *policy
			p.Grants = []tailscale.Grant{
				{Source: []string{tc.source}, Destination: []string{"tag:known:443"}, IP: []string{"tcp:443"}},
			}
			report, err := aclpolicy.EvaluateLint(&p, aclpolicy.LintOptions{})
			if err != nil {
				t.Fatal(err)
			}
			if got := countByID(report, aclpolicy.LintUndefinedReference); got != tc.wantErrors {
				t.Errorf("undefined-reference findings = %d, want %d (%#v)", got, tc.wantErrors, report.Findings)
			}
		})
	}
}

func TestEvaluateLintDstTagNoOwner(t *testing.T) {
	t.Parallel()
	// A destination tag with an owner is clean; without one it is dst-tag-no-owner
	// (not undefined-reference — the two must not double-report).
	policy := &tailscale.ACL{
		TagOwners: map[string][]string{"tag:owned": {"group:dev"}},
		Groups:    map[string][]string{"group:dev": {"alice@example.com"}},
		Grants: []tailscale.Grant{
			{Source: []string{"group:dev"}, Destination: []string{"tag:owned:443"}, IP: []string{"tcp:443"}},
			{Source: []string{"group:dev"}, Destination: []string{"tag:ownerless:443"}, IP: []string{"tcp:443"}},
		},
	}
	report, err := aclpolicy.EvaluateLint(policy, aclpolicy.LintOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if got := countByID(report, aclpolicy.LintDstTagNoOwner); got != 1 {
		t.Errorf("dst-tag-no-owner findings = %d, want 1", got)
	}
	if got := countByID(report, aclpolicy.LintUndefinedReference); got != 0 {
		t.Errorf("undefined-reference findings = %d, want 0 (dst tag must not double-report)", got)
	}
}

func TestEvaluateLintGrantEmpty(t *testing.T) {
	t.Parallel()
	appOnly := tailscale.Grant{
		Source:      []string{"group:dev"},
		Destination: []string{"tag:web"},
		App:         map[string][]map[string]any{"example.com/cap": nil},
	}
	policy := &tailscale.ACL{
		TagOwners: map[string][]string{"tag:web": {"group:dev"}},
		Groups:    map[string][]string{"group:dev": {"alice@example.com"}},
		Grants: []tailscale.Grant{
			{Source: nil, Destination: []string{"tag:web:443"}, IP: []string{"tcp:443"}}, // empty src
			{Source: []string{"group:dev"}, Destination: []string{"tag:web:443"}},        // empty ip, no app
			appOnly, // empty ip but has an app capability -> not dead
		},
	}
	report, err := aclpolicy.EvaluateLint(policy, aclpolicy.LintOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if got := countByID(report, aclpolicy.LintGrantEmpty); got != 2 {
		t.Errorf("grant-empty findings = %d, want 2 (app-only grant must not count)", got)
	}
}

func TestEvaluateLintDuplicateGrantIsOrderInsensitive(t *testing.T) {
	t.Parallel()
	policy := &tailscale.ACL{
		TagOwners: map[string][]string{"tag:web": {"group:dev"}, "tag:db": {"group:dev"}},
		Groups:    map[string][]string{"group:dev": {"alice@example.com"}},
		Grants: []tailscale.Grant{
			{
				Source:      []string{"group:dev"},
				Destination: []string{"tag:web:443", "tag:db:5432"},
				IP:          []string{"tcp:443", "tcp:5432"},
			},
			{ // same grant, selector lists in a different order
				Source:      []string{"group:dev"},
				Destination: []string{"tag:db:5432", "tag:web:443"},
				IP:          []string{"tcp:5432", "tcp:443"},
			},
		},
	}
	report, err := aclpolicy.EvaluateLint(policy, aclpolicy.LintOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if got := countByID(report, aclpolicy.LintDuplicateGrant); got != 1 {
		t.Errorf("duplicate-grant findings = %d, want 1", got)
	}
}

func TestEvaluateLintUnusedCountsIndirectReferences(t *testing.T) {
	t.Parallel()
	// group:acl is used only by a legacy ACL; group:owner only as a tag owner;
	// group:member only inside another group. None should be reported unused.
	policy := &tailscale.ACL{
		Groups: map[string][]string{
			"group:acl":    {"alice@example.com"},
			"group:owner":  {"bob@example.com"},
			"group:member": {"carol@example.com"},
			"group:parent": {"group:member"},
			"group:orphan": {"dave@example.com"},
		},
		TagOwners: map[string][]string{"tag:web": {"group:owner"}},
		ACLs: []tailscale.ACLEntry{
			{Action: "accept", Source: []string{"group:acl"}, Destination: []string{"tag:web:443"}},
		},
		Grants: []tailscale.Grant{
			{Source: []string{"group:parent"}, Destination: []string{"tag:web:443"}, IP: []string{"tcp:443"}},
		},
	}
	report, err := aclpolicy.EvaluateLint(policy, aclpolicy.LintOptions{})
	if err != nil {
		t.Fatal(err)
	}
	unused := findingsByID(report, aclpolicy.LintUnusedGroup)
	if len(unused) != 1 || unused[0].Value != "group:orphan" {
		t.Errorf("unused-group findings = %#v, want only group:orphan", unused)
	}
}

func TestEvaluateLintNilPolicy(t *testing.T) {
	t.Parallel()
	if _, err := aclpolicy.EvaluateLint(nil, aclpolicy.LintOptions{}); err == nil {
		t.Fatal("EvaluateLint(nil) returned no error")
	}
}

func TestLintSeverityHelpers(t *testing.T) {
	t.Parallel()
	if !aclpolicy.LintError.AtLeast(aclpolicy.LintWarn) || aclpolicy.LintInfo.AtLeast(aclpolicy.LintWarn) {
		t.Error("AtLeast ranking is wrong")
	}
	if _, ok := aclpolicy.ParseLintSeverity("bogus"); ok {
		t.Error("ParseLintSeverity accepted a bogus value")
	}
	if _, ok := aclpolicy.ParseWildcardPolicy("bogus"); ok {
		t.Error("ParseWildcardPolicy accepted a bogus value")
	}
	report := aclpolicy.LintReport{Findings: []aclpolicy.LintFinding{
		{Severity: aclpolicy.LintInfo}, {Severity: aclpolicy.LintWarn}, {Severity: aclpolicy.LintError},
	}}
	if got := report.CountAtLeast(aclpolicy.LintWarn); got != 2 {
		t.Errorf("CountAtLeast(warn) = %d, want 2", got)
	}
}

func countByID(report aclpolicy.LintReport, id string) int {
	return len(findingsByID(report, id))
}

func findingsByID(report aclpolicy.LintReport, id string) []aclpolicy.LintFinding {
	var matched []aclpolicy.LintFinding
	for _, finding := range report.Findings {
		if finding.ID == id {
			matched = append(matched, finding)
		}
	}
	return matched
}
