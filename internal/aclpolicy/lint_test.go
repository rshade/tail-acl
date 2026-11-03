package aclpolicy_test

import (
	"path/filepath"
	"strings"
	"testing"

	tailscale "tailscale.com/client/tailscale/v2"

	"github.com/rshade/tail-acl/internal/aclpolicy"
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

// TestEvaluateLintSCIMGroupExemption covers the SCIM/IdP-synced group
// exemption: a group:<name>@<domain> selector is not present in the local
// groups map (it resolves at the control plane), so by default it must not
// produce an undefined-reference finding and must be counted in the summary.
// Strict mode restores the error, and a domain filter narrows the exemption.
func TestEvaluateLintSCIMGroupExemption(t *testing.T) {
	t.Parallel()
	const scimGroup = "group:contractors@example.com"
	base := &tailscale.ACL{
		TagOwners: map[string][]string{"tag:web": {"autogroup:admin"}},
	}
	for _, tc := range []struct {
		name          string
		source        string
		opts          aclpolicy.LintOptions
		wantErrors    int
		wantSCIMCount int
	}{
		{
			name:          "default exempts scim group and counts it",
			source:        scimGroup,
			wantErrors:    0,
			wantSCIMCount: 1,
		},
		{
			name:          "strict errors on scim group and does not count it",
			source:        scimGroup,
			opts:          aclpolicy.LintOptions{StrictSCIMGroups: true},
			wantErrors:    1,
			wantSCIMCount: 0,
		},
		{
			name:          "listed domain is exempt",
			source:        scimGroup,
			opts:          aclpolicy.LintOptions{SCIMDomains: []string{"example.com"}},
			wantErrors:    0,
			wantSCIMCount: 1,
		},
		{
			name:          "unlisted domain still errors",
			source:        "group:contractors@other.io",
			opts:          aclpolicy.LintOptions{SCIMDomains: []string{"example.com"}},
			wantErrors:    1,
			wantSCIMCount: 0,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p := *base
			p.Grants = []tailscale.Grant{
				{Source: []string{tc.source}, Destination: []string{"tag:web"}, IP: []string{"tcp:443"}},
			}
			report, err := aclpolicy.EvaluateLint(&p, tc.opts)
			if err != nil {
				t.Fatal(err)
			}
			if got := countByID(report, aclpolicy.LintUndefinedReference); got != tc.wantErrors {
				t.Errorf("undefined-reference findings = %d, want %d (%#v)", got, tc.wantErrors, report.Findings)
			}
			if report.Summary.SCIMGroupRefs != tc.wantSCIMCount {
				t.Errorf("Summary.SCIMGroupRefs = %d, want %d", report.Summary.SCIMGroupRefs, tc.wantSCIMCount)
			}
		})
	}
}

// TestEvaluateLintSCIMGroupCountsDistinct confirms the summary tallies distinct
// SCIM-shaped selectors, not every occurrence, and that a locally declared
// group:<name>@<domain> behaves exactly as before (no exemption, no count).
func TestEvaluateLintSCIMGroupCountsDistinct(t *testing.T) {
	t.Parallel()
	policy := &tailscale.ACL{
		TagOwners: map[string][]string{"tag:web": {"autogroup:admin"}},
		Groups:    map[string][]string{"group:local@example.com": {"alice@example.com"}},
		Grants: []tailscale.Grant{
			{Source: []string{"group:a@example.com"}, Destination: []string{"tag:web"}, IP: []string{"tcp:443"}},
			{Source: []string{"group:a@example.com"}, Destination: []string{"tag:web"}, IP: []string{"tcp:80"}},
			{Source: []string{"group:b@example.com"}, Destination: []string{"tag:web"}, IP: []string{"tcp:22"}},
			// Declared locally: resolves the ordinary way, not a SCIM exemption.
			{Source: []string{"group:local@example.com"}, Destination: []string{"tag:web"}, IP: []string{"tcp:53"}},
		},
	}
	report, err := aclpolicy.EvaluateLint(policy, aclpolicy.LintOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if got := countByID(report, aclpolicy.LintUndefinedReference); got != 0 {
		t.Errorf("undefined-reference findings = %d, want 0 (%#v)", got, report.Findings)
	}
	if report.Summary.SCIMGroupRefs != 2 {
		t.Errorf("Summary.SCIMGroupRefs = %d, want 2 (distinct group:a@ and group:b@)", report.Summary.SCIMGroupRefs)
	}
}

// TestEvaluateLintServiceInSource asserts the svc: source case on its own: a
// service is destination-only, so a svc: source must warn (svc-in-source), never
// error (undefined-reference), and still be counted.
func TestEvaluateLintServiceInSource(t *testing.T) {
	t.Parallel()
	p := &tailscale.ACL{
		TagOwners: map[string][]string{"tag:server": {"autogroup:admin"}},
		Grants: []tailscale.Grant{
			{Source: []string{"svc:my-service"}, Destination: []string{"tag:server"}, IP: []string{"tcp:443"}},
		},
	}
	report, err := aclpolicy.EvaluateLint(p, aclpolicy.LintOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if got := countByID(report, aclpolicy.LintServiceInSource); got != 1 {
		t.Errorf("svc-in-source findings = %d, want 1 (%#v)", got, report.Findings)
	}
	if got := countByID(report, aclpolicy.LintUndefinedReference); got != 0 {
		t.Errorf("undefined-reference findings = %d, want 0 (svc must not double-report)", got)
	}
	for _, finding := range findingsByID(report, aclpolicy.LintServiceInSource) {
		if finding.Severity != aclpolicy.LintWarn {
			t.Errorf("svc-in-source severity = %q, want warn", finding.Severity)
		}
	}
	if report.Summary.SvcRefs != 1 {
		t.Errorf("Summary.SvcRefs = %d, want 1", report.Summary.SvcRefs)
	}
}

// TestEvaluateLintServiceInDestination asserts a svc: destination is exempt (no
// undefined-reference) and that the summary tallies distinct services.
func TestEvaluateLintServiceInDestination(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name         string
		destinations [][]string
		wantSvcRefs  int
	}{
		{name: "single dst exempt and counted", destinations: [][]string{{"svc:my-service"}}, wantSvcRefs: 1},
		{name: "distinct services counted", destinations: [][]string{{"svc:a"}, {"svc:b"}}, wantSvcRefs: 2},
		{name: "same service twice counts once", destinations: [][]string{{"svc:a"}, {"svc:a"}}, wantSvcRefs: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			grants := make([]tailscale.Grant, 0, len(tc.destinations))
			for _, destination := range tc.destinations {
				grants = append(grants, tailscale.Grant{
					Source: []string{"autogroup:member"}, Destination: destination, IP: []string{"tcp:443"},
				})
			}
			report, err := aclpolicy.EvaluateLint(&tailscale.ACL{Grants: grants}, aclpolicy.LintOptions{})
			if err != nil {
				t.Fatal(err)
			}
			if got := countByID(report, aclpolicy.LintUndefinedReference); got != 0 {
				t.Errorf("undefined-reference findings = %d, want 0 (%#v)", got, report.Findings)
			}
			if report.Summary.SvcRefs != tc.wantSvcRefs {
				t.Errorf("Summary.SvcRefs = %d, want %d", report.Summary.SvcRefs, tc.wantSvcRefs)
			}
		})
	}
}

// TestEvaluateServiceExistence covers the pure online-validation classifier with
// a collected per-selector answer set and no network. A service the control
// plane confirmed is clean; one it answered "does not exist" for is a
// svc-unknown warn; and a selector with no answer at all was never looked up, so
// it must stay silent — "could not check" is a collection failure the runner
// exits 2 on, never absence.
func TestEvaluateServiceExistence(t *testing.T) {
	t.Parallel()
	refs := []aclpolicy.ServiceRef{
		{Selector: "svc:known", Rule: "grants[0].dst[0]"},
		{Selector: "svc:ghost", Rule: "grants[1].dst[0]"},
		{Selector: "svc:unchecked", Rule: "grants[2].dst[0]"},
	}
	findings := aclpolicy.EvaluateServiceExistence(refs, map[string]bool{
		"svc:known": true,
		"svc:ghost": false,
	})
	if len(findings) != 1 {
		t.Fatalf("findings = %#v, want exactly one svc-unknown", findings)
	}
	finding := findings[0]
	if finding.ID != aclpolicy.LintServiceUnknown {
		t.Errorf("finding ID = %q, want %q", finding.ID, aclpolicy.LintServiceUnknown)
	}
	if finding.Severity != aclpolicy.LintWarn {
		t.Errorf("finding severity = %q, want warn", finding.Severity)
	}
	if finding.Value != "svc:ghost" {
		t.Errorf("finding value = %q, want svc:ghost", finding.Value)
	}
	if finding.Rule != "grants[1].dst[0]" {
		t.Errorf("finding rule = %q, want the locator of the reference", finding.Rule)
	}
}

// TestServiceDestinationRefsAreDistinctAndLocated pins the one definition of the
// set --online-validation looks up: distinct svc: selectors in a traffic
// destination, in first-occurrence order, each carrying that first locator. A
// svc: source, SSH destination, or recorder is deliberately absent — svc: is
// illegal there, so looking it up would answer a late-bound advisory question
// about a hard misuse the reference checks already report.
func TestServiceDestinationRefsAreDistinctAndLocated(t *testing.T) {
	t.Parallel()
	policy := &tailscale.ACL{
		Grants: []tailscale.Grant{
			{Source: []string{"autogroup:member"}, Destination: []string{"svc:a"}, IP: []string{"tcp:443"}},
			{Source: []string{"autogroup:member"}, Destination: []string{"svc:a"}, IP: []string{"tcp:80"}},
			{Source: []string{"svc:source-only"}, Destination: []string{"tag:web"}, IP: []string{"tcp:53"}},
		},
		ACLs: []tailscale.ACLEntry{
			{Action: "accept", Source: []string{"autogroup:member"}, Destination: []string{"svc:b:443"}},
			{Action: "accept", Users: []string{"autogroup:member"}, Ports: []string{"svc:c:8080"}},
		},
		Tests: []tailscale.ACLTest{
			{Source: "alice@example.com", Accept: []string{"svc:d:443"}, Deny: []string{"svc:e:22"}},
			{User: "bob@example.com", Allow: []string{"svc:f:443"}},
		},
		SSH: []tailscale.ACLSSH{
			{Source: []string{"autogroup:member"}, Destination: []string{"svc:ssh-dst"},
				Users: []string{"root"}, Recorder: []string{"svc:recorder"}},
		},
	}
	want := []aclpolicy.ServiceRef{
		{Selector: "svc:a", Rule: "grants[0].dst[0]"},
		{Selector: "svc:b", Rule: "acls[0].dst[0]"},
		{Selector: "svc:c", Rule: "acls[1].ports[0]"},
		{Selector: "svc:d", Rule: "tests[0].accept[0]"},
		{Selector: "svc:e", Rule: "tests[0].deny[0]"},
		{Selector: "svc:f", Rule: "tests[1].accept[0]"},
	}
	got := aclpolicy.ServiceDestinationRefs(policy)
	if len(got) != len(want) {
		t.Fatalf("ServiceDestinationRefs = %#v, want %#v", got, want)
	}
	for index, ref := range want {
		if got[index] != ref {
			t.Errorf("ref[%d] = %#v, want %#v", index, got[index], ref)
		}
	}
}

// TestEvaluateLintCountsServicesNamedOnlyByPolicyTests is the defect-1
// regression guard: a service named only by a test assertion was looked up by
// --online-validation yet never counted in svc_refs, so the count silently
// under-reported exactly the references the online pass checks.
func TestEvaluateLintCountsServicesNamedOnlyByPolicyTests(t *testing.T) {
	t.Parallel()
	policy := &tailscale.ACL{
		TagOwners: map[string][]string{"tag:web": {"autogroup:admin"}},
		Grants: []tailscale.Grant{
			{Source: []string{"autogroup:member"}, Destination: []string{"tag:web"}, IP: []string{"tcp:443"}},
		},
		Tests: []tailscale.ACLTest{
			{Source: "alice@example.com", Accept: []string{"svc:accepted:443"}, Deny: []string{"svc:denied:22"}},
			{User: "bob@example.com", Allow: []string{"svc:allowed:443"}},
		},
	}
	report, err := aclpolicy.EvaluateLint(policy, aclpolicy.LintOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if report.Summary.SvcRefs != 3 {
		t.Errorf("Summary.SvcRefs = %d, want 3 (accept, deny, and allow assertions)", report.Summary.SvcRefs)
	}
	if report.Summary.SvcDstRefs != 3 {
		t.Errorf("Summary.SvcDstRefs = %d, want 3; every test assertion is an online-checkable position",
			report.Summary.SvcDstRefs)
	}
}

// TestLintSummarySeparatesReferencedFromCheckableServices is the defect-2
// regression guard: svc_refs counts every distinct service the policy names,
// including positions where svc: is illegal and no lookup is made, so reading it
// as online coverage over-states what was verified. svc_dst_refs reports the
// online-checkable subset, and the two must not be the same number here. The
// autoApprovers.services map key is a container key rather than a selector the
// linter resolves, so it is in neither count — five, not six.
func TestLintSummarySeparatesReferencedFromCheckableServices(t *testing.T) {
	t.Parallel()
	policy := &tailscale.ACL{
		TagOwners: map[string][]string{"tag:web": {"autogroup:admin"}},
		Grants: []tailscale.Grant{
			{Source: []string{"autogroup:member"}, Destination: []string{"svc:checked"}, IP: []string{"tcp:443"}},
			{Source: []string{"svc:in-source"}, Destination: []string{"tag:web"}, IP: []string{"tcp:80"}},
		},
		SSH: []tailscale.ACLSSH{
			{Action: "accept", Source: []string{"autogroup:member"}, Destination: []string{"svc:ssh-dst"},
				Users: []string{"root"}, Recorder: []string{"svc:recorder"}},
		},
		AutoApprovers: &tailscale.ACLAutoApprovers{
			Services: map[string][]string{"svc:web": {"svc:approver"}},
		},
	}
	report, err := aclpolicy.EvaluateLint(policy, aclpolicy.LintOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if report.Summary.SvcRefs != 5 {
		t.Errorf("Summary.SvcRefs = %d, want 5 (dst, src, ssh dst, recorder, approver value); findings %#v",
			report.Summary.SvcRefs, report.Findings)
	}
	if report.Summary.SvcDstRefs != 1 {
		t.Errorf("Summary.SvcDstRefs = %d, want 1 (only the grant destination is online-checkable)",
			report.Summary.SvcDstRefs)
	}
	if report.Summary.SvcDstRefs > report.Summary.SvcRefs {
		t.Errorf("online-checkable subset %d exceeds the referenced count %d",
			report.Summary.SvcDstRefs, report.Summary.SvcRefs)
	}
	invalidSSH := findingsByID(report, aclpolicy.LintServiceInSSH)
	if len(invalidSSH) != 2 {
		t.Fatalf("invalid SSH service findings = %#v, want dst and recorder findings", invalidSSH)
	}
	wantRules := map[string]bool{
		"ssh[0].dst[0]":      false,
		"ssh[0].recorder[0]": false,
	}
	for _, finding := range invalidSSH {
		if _, ok := wantRules[finding.Rule]; ok {
			wantRules[finding.Rule] = true
		}
	}
	for rule, found := range wantRules {
		if !found {
			t.Errorf("missing invalid SSH service finding at %s in %#v", rule, invalidSSH)
		}
	}
}

// TestEvaluateSCIMGroupSync covers the pure classifier behind the SCIM half of
// lint --online-validation, fed captured control-plane warning strings with no
// network.
func TestEvaluateSCIMGroupSync(t *testing.T) {
	t.Parallel()
	const notSyncing = " is not syncing from SCIM and will be ignored by rules in the policy file"
	tests := []struct {
		name                 string
		warnings             []string
		wantCount            int
		wantValue            string
		wantEvidenceContains string
	}{
		{
			name:      "warning names the group selector",
			warnings:  []string{"group:contractors@example.com" + notSyncing},
			wantCount: 1,
			wantValue: "group:contractors@example.com",
		},
		{
			name: "same group twice is deduplicated",
			warnings: []string{
				"group:contractors@example.com" + notSyncing,
				"group:contractors@example.com" + notSyncing,
			},
			wantCount: 1,
			wantValue: "group:contractors@example.com",
		},
		{
			name:                 "warning without a group token still reports",
			warnings:             []string{"a referenced entity is not syncing from SCIM and will be ignored"},
			wantCount:            1,
			wantValue:            "",
			wantEvidenceContains: "not syncing from SCIM",
		},
		{
			name:      "unrelated warning is ignored",
			warnings:  []string{"some other warning"},
			wantCount: 0,
		},
		{
			name:      "empty input",
			warnings:  nil,
			wantCount: 0,
		},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			findings := aclpolicy.EvaluateSCIMGroupSync(testCase.warnings)
			if findings == nil {
				t.Fatal("findings = nil, want non-nil slice")
			}
			if len(findings) != testCase.wantCount {
				t.Fatalf("findings = %#v, want %d", findings, testCase.wantCount)
			}
			if testCase.wantCount == 0 {
				return
			}
			assertSCIMFinding(t, findings[0], testCase.wantValue, testCase.wantEvidenceContains)
		})
	}
}

func assertSCIMFinding(t *testing.T, finding aclpolicy.LintFinding, wantValue, wantEvidenceContains string) {
	t.Helper()
	if finding.ID != aclpolicy.LintSCIMGroupUnknown {
		t.Errorf("finding ID = %q, want %q", finding.ID, aclpolicy.LintSCIMGroupUnknown)
	}
	if finding.Severity != aclpolicy.LintWarn {
		t.Errorf("finding severity = %q, want warn", finding.Severity)
	}
	if finding.Value != wantValue {
		t.Errorf("finding value = %q, want %q", finding.Value, wantValue)
	}
	if wantEvidenceContains != "" && !strings.Contains(finding.Evidence, wantEvidenceContains) {
		t.Errorf("finding evidence = %q, want it to contain %q", finding.Evidence, wantEvidenceContains)
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
		TagOwners: map[string][]string{
			"tag:ssh-only": {"autogroup:admin"},
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
		TagOwners: map[string][]string{
			"tag:ssh-only": {"autogroup:admin"},
			"tag:recorder": {"autogroup:admin"},
		},
		SSH: []aclpolicy.SSHRule{{
			Action:      "accept",
			Source:      []string{"autogroup:member"},
			Destination: []string{"tag:ssh-only"},
			Users:       []string{"ubuntu"},
			Recorder:    []string{"tag:recorder"},
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
			Action:      "accept",
			Source:      []string{"group:ghost"},
			Destination: []string{"tag:missing"},
			Users:       []string{"ubuntu"},
			Recorder:    []string{"recorder-missing"},
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
	if !aclpolicy.LintError.AtLeast(aclpolicy.LintWarn) || aclpolicy.LintInfo.AtLeast(aclpolicy.LintWarn) ||
		aclpolicy.LintAdvice.AtLeast(aclpolicy.LintInfo) {
		t.Error("AtLeast ranking is wrong")
	}
	if severity, ok := aclpolicy.ParseLintSeverity("advice"); !ok || severity != aclpolicy.LintAdvice {
		t.Error("ParseLintSeverity rejected advice")
	}
	if _, ok := aclpolicy.ParseLintSeverity("bogus"); ok {
		t.Error("ParseLintSeverity accepted a bogus value")
	}
	if _, ok := aclpolicy.ParseWildcardPolicy("bogus"); ok {
		t.Error("ParseWildcardPolicy accepted a bogus value")
	}
	report := aclpolicy.LintReport{Findings: []aclpolicy.LintFinding{
		{Severity: aclpolicy.LintAdvice}, {Severity: aclpolicy.LintInfo},
		{Severity: aclpolicy.LintWarn}, {Severity: aclpolicy.LintError},
	}}
	if got := report.CountAtLeast(aclpolicy.LintWarn); got != 2 {
		t.Errorf("CountAtLeast(warn) = %d, want 2", got)
	}
	if got := report.CountAtLeast(aclpolicy.LintAdvice); got != 4 {
		t.Errorf("CountAtLeast(advice) = %d, want 4", got)
	}
}

// TestEvaluateLintPostureReferences pins the posture half of
// undefined-reference: a srcPosture or defaultSrcPosture entry naming a
// posture the policy does not define is a dangling reference like any other,
// and the finding names the position it came from. Names resolve with
// NormalizePostureName, so a bare name lint accepts is the name posture set
// writes.
func TestEvaluateLintPostureReferences(t *testing.T) {
	t.Parallel()
	policy := &tailscale.ACL{
		TagOwners: map[string][]string{"tag:web": {"group:dev"}},
		Groups:    map[string][]string{"group:dev": {"alice@example.com"}},
		Postures: map[string][]string{
			"posture:defined": {"custom:defined == true"},
		},
		DefaultSourcePosture: []string{"posture:missing-default"},
		Grants: []tailscale.Grant{
			{
				Source:      []string{"group:dev"},
				Destination: []string{"tag:web"},
				IP:          []string{"tcp:443"},
				SrcPosture:  []string{"posture:missing-grant", "posture:defined"},
			},
		},
		ACLs: []tailscale.ACLEntry{
			{
				Action:        "accept",
				Source:        []string{"alice@example.com"},
				Destination:   []string{"tag:web:443"},
				SourcePosture: []string{"posture:missing-acl"},
			},
		},
	}
	report, err := aclpolicy.EvaluateLint(policy, aclpolicy.LintOptions{})
	if err != nil {
		t.Fatal(err)
	}
	findings := findingsByID(report, aclpolicy.LintUndefinedReference)
	if len(findings) != 3 {
		t.Fatalf("undefined-reference findings = %#v, want one per missing posture", findings)
	}
	wantRules := map[string]string{
		"grants[0].srcPosture[0]": "posture:missing-grant",
		"acls[0].srcPosture[0]":   "posture:missing-acl",
		"defaultSrcPosture[0]":    "posture:missing-default",
	}
	for _, finding := range findings {
		want, ok := wantRules[finding.Rule]
		if !ok {
			t.Errorf("unexpected finding at %s", finding.Rule)
			continue
		}
		if finding.Value != want {
			t.Errorf("finding at %s has Value %q, want %q", finding.Rule, finding.Value, want)
		}
		if finding.Severity != aclpolicy.LintError {
			t.Errorf("finding at %s has Severity %q, want error", finding.Rule, finding.Severity)
		}
		delete(wantRules, finding.Rule)
	}
	if len(wantRules) != 0 {
		t.Errorf("missing findings for %v", wantRules)
	}
	if countByID(report, aclpolicy.LintUnusedPosture) != 0 {
		t.Errorf("unused-posture findings = %#v, want none: posture:defined is referenced by the grant",
			findingsByID(report, aclpolicy.LintUnusedPosture))
	}
}

// TestEvaluateLintUnusedPosture pins the unused-posture rule, including the
// defaultSrcPosture exemption: a posture referenced only by the tailnet-wide
// default is used, or a policy gating everything through the default would
// flag every posture it uses.
func TestEvaluateLintUnusedPosture(t *testing.T) {
	t.Parallel()
	policy := &tailscale.ACL{
		TagOwners: map[string][]string{"tag:web": {"alice@example.com"}},
		Postures: map[string][]string{
			"posture:unused":           {"custom:unused == true"},
			"posture:defaulted":        {"custom:defaulted == true"},
			"posture:grant-referenced": {"custom:used == true"},
		},
		DefaultSourcePosture: []string{"posture:defaulted"},
		Grants: []tailscale.Grant{
			{
				Source:      []string{"alice@example.com"},
				Destination: []string{"tag:web"},
				IP:          []string{"tcp:443"},
				SrcPosture:  []string{"posture:grant-referenced"},
			},
		},
	}
	report, err := aclpolicy.EvaluateLint(policy, aclpolicy.LintOptions{})
	if err != nil {
		t.Fatal(err)
	}
	findings := findingsByID(report, aclpolicy.LintUnusedPosture)
	if len(findings) != 1 {
		t.Fatalf("unused-posture findings = %#v, want only posture:unused", findings)
	}
	if findings[0].Value != "posture:unused" {
		t.Errorf("unused-posture Value = %q, want posture:unused", findings[0].Value)
	}
	if findings[0].Severity != aclpolicy.LintInfo {
		t.Errorf("unused-posture Severity = %q, want info", findings[0].Severity)
	}
}

// TestEvaluateLintPostureInvalid pins the posture-invalid rule against the
// three expressions from the Features/03 write-up, each reproduced against
// the control plane on 2026-10-02: an out-of-vocabulary ip:country value and
// an unparseable expression are errors (the server rejects the policy over
// both), while an unknown node: attribute is a warn, because the
// known-attribute table is editorial and goes stale.
func TestEvaluateLintPostureInvalid(t *testing.T) {
	t.Parallel()
	policy := &tailscale.ACL{
		TagOwners: map[string][]string{"tag:web": {"alice@example.com"}},
		Postures: map[string][]string{
			"posture:geo":     {"ip:country NOT IN ['AB', 'CD']"},
			"posture:garbage": {"this is not an expression"},
			"posture:bogus":   {"node:bogusattr == 'x'"},
			"posture:clean":   {"node:os == 'linux'", "custom:madeUp == true", "ip:country IN ['US', 'XK']"},
		},
		Grants: []tailscale.Grant{
			{
				Source:      []string{"alice@example.com"},
				Destination: []string{"tag:web"},
				IP:          []string{"tcp:443"},
				SrcPosture:  []string{"posture:geo", "posture:garbage", "posture:bogus", "posture:clean"},
			},
		},
	}
	report, err := aclpolicy.EvaluateLint(policy, aclpolicy.LintOptions{})
	if err != nil {
		t.Fatal(err)
	}
	findings := findingsByID(report, aclpolicy.LintPostureInvalid)
	want := map[string]struct {
		severity aclpolicy.LintSeverity
		evidence []string
	}{
		"postures[posture:geo][0]": {
			aclpolicy.LintError,
			[]string{"posture:geo", "ip:country NOT IN ['AB', 'CD']", `unexpected value "AB"`},
		},
		"postures[posture:garbage][0]": {
			aclpolicy.LintError,
			[]string{"posture:garbage", "this is not an expression", "expected an operator", "valid operators are:"},
		},
		"postures[posture:bogus][0]": {
			aclpolicy.LintWarn,
			[]string{"posture:bogus", "node:bogusattr == 'x'", `attribute "node:bogusattr" does not exist`},
		},
	}
	if len(findings) != len(want) {
		t.Fatalf("posture-invalid findings = %#v, want one per write-up expression", findings)
	}
	for _, finding := range findings {
		expected, ok := want[finding.Rule]
		if !ok {
			t.Errorf("unexpected finding at %s: %#v", finding.Rule, finding)
			continue
		}
		if finding.Severity != expected.severity {
			t.Errorf("finding at %s has Severity %q, want %q", finding.Rule, finding.Severity, expected.severity)
		}
		for _, fragment := range expected.evidence {
			if !strings.Contains(finding.Evidence, fragment) {
				t.Errorf("finding at %s has Evidence %q, want it to contain %q",
					finding.Rule, finding.Evidence, fragment)
			}
		}
		delete(want, finding.Rule)
	}
	if len(want) != 0 {
		t.Errorf("missing findings for %v", want)
	}
}

func countByID(report aclpolicy.LintReport, id string) int {
	return len(findingsByID(report, id))
}

// TestEvaluateLintAutoApproverReferences pins the autoApprovers walk of
// undefined-reference: an approver naming an undefined group/tag or an illegal
// selector kind silently approves nothing, so it must be reported exactly like
// a grant's dangling selector. Users, autogroups, and defined groups/tags must
// not. The reverse coherence matters too — legal definitions referenced only
// by an approver are used, while an illegal host/ipset does not suppress the
// corresponding unused-definition finding.
func TestEvaluateLintAutoApproverReferences(t *testing.T) {
	t.Parallel()
	policy := &tailscale.ACL{
		Groups:    map[string][]string{"group:known": {"alice@example.com"}},
		Hosts:     map[string]string{"web": "100.64.0.8"},
		IPSets:    map[string][]string{"ipset:corp": {"10.0.0.0/8"}},
		TagOwners: map[string][]string{"tag:known": {"group:known"}},
		AutoApprovers: &tailscale.ACLAutoApprovers{
			Routes: map[string][]string{
				"10.0.0.0/8": {
					"group:known",
					"group:ghost",
					"web",
					"ipset:corp",
					"100.64.0.1",
				},
				"192.168.0.0/24": {"tag:ghost"},
			},
			ExitNode: []string{
				"tag:known",
				"autogroup:admin",
				"alice@example.com",
				"10.0.0.0/8",
			},
			Services: map[string][]string{"svc:web": {"group:ghostsvc"}},
		},
	}
	report, err := aclpolicy.EvaluateLint(policy, aclpolicy.LintOptions{})
	if err != nil {
		t.Fatal(err)
	}
	findings := findingsByID(report, aclpolicy.LintUndefinedReference)
	got := make(map[string]string, len(findings))
	for _, finding := range findings {
		got[finding.Rule] = finding.Value
	}
	want := map[string]string{
		"autoApprovers.routes[10.0.0.0/8][1]":     "group:ghost",
		"autoApprovers.routes[10.0.0.0/8][2]":     "web",
		"autoApprovers.routes[10.0.0.0/8][3]":     "ipset:corp",
		"autoApprovers.routes[10.0.0.0/8][4]":     "100.64.0.1",
		"autoApprovers.routes[192.168.0.0/24][0]": "tag:ghost",
		"autoApprovers.exitNode[3]":               "10.0.0.0/8",
		"autoApprovers.services[svc:web][0]":      "group:ghostsvc",
	}
	if len(got) != len(want) {
		t.Errorf("undefined-reference findings = %v, want %v", got, want)
	}
	for rule, value := range want {
		if got[rule] != value {
			t.Errorf("finding at %q = %q, want %q (all: %v)", rule, got[rule], value, got)
		}
	}
	if got := countByID(report, aclpolicy.LintUnusedGroup); got != 0 {
		t.Errorf("group referenced only by an approver reported unused: %#v",
			findingsByID(report, aclpolicy.LintUnusedGroup))
	}
	if got := countByID(report, aclpolicy.LintUnusedTag); got != 0 {
		t.Errorf("tag referenced only by an approver reported unused: %#v",
			findingsByID(report, aclpolicy.LintUnusedTag))
	}
	if got := countByID(report, aclpolicy.LintUnusedHost); got != 1 {
		t.Errorf("illegal auto-approver host suppressed unused-host: %#v",
			findingsByID(report, aclpolicy.LintUnusedHost))
	}
	if got := countByID(report, aclpolicy.LintUnusedIPSet); got != 1 {
		t.Errorf("illegal auto-approver ipset suppressed unused-ipset: %#v",
			findingsByID(report, aclpolicy.LintUnusedIPSet))
	}
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

// TestEvaluateLintCountsNodeAttrAndViaReferences pins the two selector fields
// the unused-definition walk once skipped. The omission was not merely a
// missed finding: lint reported a live definition as unused and recommended
// deleting it, and tail-acl's own definition removal would then carry that
// recommendation out without asking for --force.
func TestEvaluateLintCountsNodeAttrAndViaReferences(t *testing.T) {
	t.Parallel()
	policy := &tailscale.ACL{
		Groups: map[string][]string{"group:eng": {"alice@example.com"}},
		IPSets: map[string][]string{"ipset:office": {"10.0.0.0/8"}},
		NodeAttrs: []tailscale.NodeAttrGrant{
			{Target: []string{"group:eng"}, Attr: []string{"funnel"}},
		},
		Grants: []tailscale.Grant{
			{
				Source:      []string{"autogroup:member"},
				Destination: []string{"tag:web"},
				IP:          []string{"tcp:443"},
				Via:         []string{"ipset:office"},
			},
		},
	}
	report, err := aclpolicy.EvaluateLint(policy, aclpolicy.LintOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if unused := findingsByID(report, aclpolicy.LintUnusedGroup); len(unused) != 0 {
		t.Errorf("unused-group findings = %#v, want none for a nodeAttrs target", unused)
	}
	if unused := findingsByID(report, aclpolicy.LintUnusedIPSet); len(unused) != 0 {
		t.Errorf("unused-ipset findings = %#v, want none for a grant via-router", unused)
	}
}

func TestEvaluateLintCountsNodeAttrAppConnectorReferences(t *testing.T) {
	t.Parallel()
	policy := &tailscale.ACL{
		Groups: map[string][]string{"group:eng": {"alice@example.com"}},
		IPSets: map[string][]string{"ipset:office": {"10.0.0.0/8"}},
		NodeAttrs: []tailscale.NodeAttrGrant{{
			Target: []string{"*"},
			App: map[string][]*tailscale.NodeAttrGrantApp{
				"tailscale.com/app-connectors": {{
					Connectors: []string{"group:eng", "ipset:office"},
				}},
			},
		}},
	}
	report, err := aclpolicy.EvaluateLint(policy, aclpolicy.LintOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if unused := findingsByID(report, aclpolicy.LintUnusedGroup); len(unused) != 0 {
		t.Errorf("unused-group findings = %#v, want none for an app connector", unused)
	}
	if unused := findingsByID(report, aclpolicy.LintUnusedIPSet); len(unused) != 0 {
		t.Errorf("unused-ipset findings = %#v, want none for an app connector", unused)
	}
}
