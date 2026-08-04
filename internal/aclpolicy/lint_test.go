package aclpolicy_test

import (
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
	report, err := aclpolicy.EvaluatePolicyLint(policy, aclpolicy.LintOptions{})
	if err != nil {
		t.Fatal(err)
	}
	assertGolden(t, "lint_report.golden.json", report)
}

func TestEvaluateLintCleanPolicyHasNoFindings(t *testing.T) {
	t.Parallel()
	policy := &tailscale.ACL{
		Groups:    map[string][]string{"group:dev": {"alice@example.com"}},
		TagOwners: map[string][]string{"tag:web": {"group:dev"}},
		Grants: []tailscale.Grant{
			{Source: []string{"group:dev"}, Destination: []string{"tag:web"}, IP: []string{"tcp:443"}},
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
			{Source: []string{"*"}, Destination: []string{"tag:web"}, IP: []string{"tcp:443"}},
			{Source: []string{"group:dev"}, Destination: []string{"*"}, IP: []string{"tcp:443"}},
			{Source: []string{"*"}, Destination: []string{"*"}, IP: []string{"tcp:443"}},
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
				{Source: []string{tc.source}, Destination: []string{"tag:known"}, IP: []string{"tcp:443"}},
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

func TestEvaluateLintPortlessGrantDestinationsResolve(t *testing.T) {
	t.Parallel()
	policy := &tailscale.ACL{
		Groups:    map[string][]string{"group:known": {"alice@example.com"}},
		Hosts:     map[string]string{"known-host": "100.64.0.9"},
		IPSets:    map[string][]string{"ipset:known": {"10.0.0.0/8"}},
		TagOwners: map[string][]string{"tag:known": {"group:known"}},
		Grants: []tailscale.Grant{
			{Source: []string{"autogroup:member"}, Destination: []string{"tag:known"}, IP: []string{"tcp:443"}},
			{Source: []string{"autogroup:member"}, Destination: []string{"group:known"}, IP: []string{"tcp:443"}},
			{Source: []string{"autogroup:member"}, Destination: []string{"ipset:known"}, IP: []string{"tcp:443"}},
			{
				Source:      []string{"autogroup:member"},
				Destination: []string{"autogroup:internet"},
				IP:          []string{"tcp:443"},
			},
			{Source: []string{"autogroup:member"}, Destination: []string{"known-host"}, IP: []string{"tcp:443"}},
			{Source: []string{"autogroup:member"}, Destination: []string{"100.64.0.10"}, IP: []string{"tcp:443"}},
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

// TestLintAndCheckAgreeOnPortlessGrantDestination guards the contradiction that
// motivated the portless-dst fix: on issue #92's reproduction policy, check
// reported the grant reachable while lint called the same destination undefined.
func TestLintAndCheckAgreeOnPortlessGrantDestination(t *testing.T) {
	t.Parallel()
	policy := &tailscale.ACL{
		TagOwners: map[string][]string{"tag:web": {"autogroup:admin"}},
		Grants: []tailscale.Grant{
			{Source: []string{"autogroup:member"}, Destination: []string{"tag:web"}, IP: []string{"tcp:443"}},
		},
	}

	reach, err := aclpolicy.EvaluateReachability(policy, "autogroup:member", "tag:web:443",
		aclpolicy.ReachabilityOptions{Protocol: aclpolicy.ProtocolTCP})
	if err != nil {
		t.Fatal(err)
	}
	if reach.Allowed == nil || !*reach.Allowed {
		t.Fatalf("check access = %q, allowed = %v, want reachable", reach.Access, reach.Allowed)
	}

	report, err := aclpolicy.EvaluateLint(policy, aclpolicy.LintOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if got := countByID(report, aclpolicy.LintUndefinedReference); got != 0 {
		t.Errorf("lint calls a destination check reached undefined: %#v",
			findingsByID(report, aclpolicy.LintUndefinedReference))
	}
	if got := countByID(report, aclpolicy.LintUnusedTag); got != 0 {
		t.Errorf("lint calls an in-use tag unused: %#v", findingsByID(report, aclpolicy.LintUnusedTag))
	}
}

func TestEvaluateLintACLDestinationStillStripsPort(t *testing.T) {
	t.Parallel()
	policy := &tailscale.ACL{
		Groups:    map[string][]string{"group:dev": {"alice@example.com"}},
		TagOwners: map[string][]string{"tag:db": {"group:dev"}},
		ACLs: []tailscale.ACLEntry{
			{
				Action:      "accept",
				Source:      []string{"group:dev"},
				Destination: []string{"tag:db:5432"},
			},
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

func TestEvaluateLintDstTagNoOwner(t *testing.T) {
	t.Parallel()
	// A destination tag with an owner is clean; without one it is dst-tag-no-owner
	// (not undefined-reference — the two must not double-report).
	policy := &tailscale.ACL{
		TagOwners: map[string][]string{"tag:owned": {"group:dev"}},
		Groups:    map[string][]string{"group:dev": {"alice@example.com"}},
		Grants: []tailscale.Grant{
			{Source: []string{"group:dev"}, Destination: []string{"tag:owned"}, IP: []string{"tcp:443"}},
			{Source: []string{"group:dev"}, Destination: []string{"tag:ownerless"}, IP: []string{"tcp:443"}},
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
			{Source: nil, Destination: []string{"tag:web"}, IP: []string{"tcp:443"}}, // empty src
			{Source: []string{"group:dev"}, Destination: []string{"tag:web"}},        // empty ip, no app
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
				Destination: []string{"tag:web", "tag:db"},
				IP:          []string{"tcp:443", "tcp:5432"},
			},
			{ // same grant, selector lists in a different order
				Source:      []string{"group:dev"},
				Destination: []string{"tag:db", "tag:web"},
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
			{Source: []string{"group:parent"}, Destination: []string{"tag:web"}, IP: []string{"tcp:443"}},
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

func TestEvaluatePolicyLintCountsSSHTestReferences(t *testing.T) {
	t.Parallel()
	policy := &aclpolicy.Policy{
		ACL: tailscale.ACL{
			TagOwners: map[string][]string{
				"tag:ssh-only": {"autogroup:admin"},
			},
		},
		SSHTests: []aclpolicy.SSHTest{{
			Source:      "alice@example.com",
			Destination: []string{"tag:ssh-only"},
			Accept:      []string{"ubuntu"},
		}},
	}
	report, err := aclpolicy.EvaluatePolicyLint(policy, aclpolicy.LintOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if got := countByID(report, aclpolicy.LintUnusedTag); got != 0 {
		t.Errorf("unused-tag findings = %d, want none (%#v)", got, report.Findings)
	}
}

// TestEvaluatePolicyLintCountsSSHRuleReferences builds the Policy by hand rather
// than through Load, so it also pins that EvaluatePolicyLint derives SSH rules
// from Policy.SSH instead of the ACL.SSH mirror that only Load populates.
func TestEvaluatePolicyLintCountsSSHRuleReferences(t *testing.T) {
	t.Parallel()
	policy := &aclpolicy.Policy{
		ACL: tailscale.ACL{
			TagOwners: map[string][]string{
				"tag:ssh-only": {"autogroup:admin"},
				"tag:recorder": {"autogroup:admin"},
			},
		},
		SSH: []aclpolicy.SSHRule{{
			ACLSSH: tailscale.ACLSSH{
				Action:      "accept",
				Source:      []string{"autogroup:member"},
				Destination: []string{"tag:ssh-only"},
				Users:       []string{"ubuntu"},
				Recorder:    []string{"tag:recorder"},
			},
		}},
	}
	report, err := aclpolicy.EvaluatePolicyLint(policy, aclpolicy.LintOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if got := countByID(report, aclpolicy.LintUnusedTag); got != 0 {
		t.Errorf("unused-tag findings = %d, want none (%#v)", got, report.Findings)
	}
}

// TestEvaluateLintCountsSSHRuleReferences covers the same gap on the raw-ACL
// entry point, which the pinned client models without any local extension.
func TestEvaluateLintCountsSSHRuleReferences(t *testing.T) {
	t.Parallel()
	policy := &tailscale.ACL{
		TagOwners: map[string][]string{"tag:ssh-only": {"autogroup:admin"}},
		SSH: []tailscale.ACLSSH{{
			Action:      "accept",
			Source:      []string{"autogroup:member"},
			Destination: []string{"tag:ssh-only"},
			Users:       []string{"ubuntu"},
		}},
	}
	report, err := aclpolicy.EvaluateLint(policy, aclpolicy.LintOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if got := countByID(report, aclpolicy.LintUnusedTag); got != 0 {
		t.Errorf("unused-tag findings = %d, want none (%#v)", got, report.Findings)
	}
}

func TestEvaluatePolicyLintFlagsInvalidSSHSelectors(t *testing.T) {
	t.Parallel()
	policy := &aclpolicy.Policy{
		SSH: []aclpolicy.SSHRule{{
			ACLSSH: tailscale.ACLSSH{
				Action:      "accept",
				Source:      []string{"group:ghost"},
				Destination: []string{"tag:missing"},
				Users:       []string{"ubuntu"},
				Recorder:    []string{"recorder-missing"},
			},
		}},
		SSHTests: []aclpolicy.SSHTest{{
			Source:      "ipset:ghost",
			Destination: []string{"tag:test-missing"},
			Accept:      []string{"ubuntu"},
		}},
	}
	report, err := aclpolicy.EvaluatePolicyLint(policy, aclpolicy.LintOptions{})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{
		"undefined-reference|ssh[0].src[0]|group:ghost":           false,
		"dst-tag-no-owner|ssh[0].dst[0]|tag:missing":              false,
		"undefined-reference|ssh[0].recorder[0]|recorder-missing": false,
		"undefined-reference|sshTests[0].src|ipset:ghost":         false,
		"dst-tag-no-owner|sshTests[0].dst[0]|tag:test-missing":    false,
	}
	for _, finding := range report.Findings {
		key := finding.ID + "|" + finding.Rule + "|" + finding.Value
		if _, ok := want[key]; ok {
			want[key] = true
		}
	}
	for key, found := range want {
		if !found {
			t.Errorf("missing finding %q in %#v", key, report.Findings)
		}
	}
	if report.Summary.Error != len(want) || report.Summary.Total != len(want) {
		t.Errorf("summary = %#v, want %d errors and no other findings", report.Summary, len(want))
	}
}

func TestEvaluateLintNilPolicy(t *testing.T) {
	t.Parallel()
	if _, err := aclpolicy.EvaluateLint(nil, aclpolicy.LintOptions{}); err == nil {
		t.Fatal("EvaluateLint(nil) returned no error")
	}
	if _, err := aclpolicy.EvaluatePolicyLint(nil, aclpolicy.LintOptions{}); err == nil {
		t.Fatal("EvaluatePolicyLint(nil) returned no error")
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

// TestEvaluateLintDoesNotFlagSrcPostureOrPostures is a scope-boundary guard: a
// grant's srcPosture naming an undeclared posture, and a postures entry
// referenced by no grant, must produce zero lint findings. Dangling/unused
// posture validation is issue #17's job, not this issue's — see the plan's
// Risks section. This must fail loudly if a future change wires
// postures/srcPosture into undefinedReferenceReason or the unused-definition
// checks prematurely.
func TestEvaluateLintDoesNotFlagSrcPostureOrPostures(t *testing.T) {
	t.Parallel()
	policy := &tailscale.ACL{
		TagOwners: map[string][]string{"tag:web": {"group:dev"}},
		Groups:    map[string][]string{"group:dev": {"alice@example.com"}},
		Postures: map[string][]string{
			"posture:unused": {"custom:unused == true"},
		},
		Grants: []tailscale.Grant{
			{
				Source:      []string{"group:dev"},
				Destination: []string{"tag:web"},
				IP:          []string{"tcp:443"},
				SrcPosture:  []string{"posture:undeclared"},
			},
		},
	}
	report, err := aclpolicy.EvaluateLint(policy, aclpolicy.LintOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if report.Summary.Total != 0 {
		t.Errorf("findings = %#v, want none (srcPosture/postures are out of lint's scope)", report.Findings)
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
