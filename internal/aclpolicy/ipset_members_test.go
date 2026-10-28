package aclpolicy_test

import (
	"slices"
	"strings"
	"testing"

	tailscale "tailscale.com/client/tailscale/v2"

	"github.com/rshade/tailscale-utils/tail-acl/internal/aclpolicy"
)

func TestLintIPSetMembers(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name    string
		policy  *tailscale.ACL
		id      string
		want    int
		contain string
		also    string
	}{
		{
			name: "bare name",
			policy: &tailscale.ACL{
				Hosts:  map[string]string{"gw": "10.10.20.1"},
				IPSets: map[string][]string{"ipset:p": {"gw"}},
			},
			id:      aclpolicy.LintIPSetMemberInvalid,
			want:    1,
			contain: `ipset:p member "gw"`,
		},
		{
			name: "missing host",
			policy: &tailscale.ACL{
				IPSets: map[string][]string{"ipset:p": {"host:missing"}},
			},
			id:      aclpolicy.LintIPSetReferenceUndefined,
			want:    1,
			contain: "host:missing",
		},
		{
			name: "missing ipset",
			policy: &tailscale.ACL{
				IPSets: map[string][]string{"ipset:p": {"ipset:nope"}},
			},
			id:      aclpolicy.LintIPSetReferenceUndefined,
			want:    1,
			contain: "ipset:nope",
		},
		{
			name: "cycle",
			policy: &tailscale.ACL{
				IPSets: map[string][]string{
					"ipset:p": {"ipset:q"},
					"ipset:q": {"ipset:p"},
				},
			},
			id:      aclpolicy.LintIPSetReferenceCycle,
			want:    1,
			contain: "ipset:p -> ipset:q -> ipset:p",
		},
		{
			name: "host value is a tag",
			policy: &tailscale.ACL{
				Hosts:  map[string]string{"gw": "tag:web"},
				IPSets: map[string][]string{"ipset:p": {"host:gw"}},
			},
			id:      aclpolicy.LintHostNotAddress,
			want:    1,
			contain: `value "tag:web"`,
			also:    `ipset ipset:p member "host:gw"`,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			matched := findingsWithID(t, test.policy, test.id)
			if len(matched) != test.want {
				t.Fatalf("findings = %#v", matched)
			}
			if test.want == 0 {
				return
			}
			if matched[0].Severity != aclpolicy.LintError {
				t.Fatalf("severity = %s", matched[0].Severity)
			}
			got := matched[0].Evidence + " " + matched[0].Rule
			if !strings.Contains(got, test.contain) || (test.also != "" && !strings.Contains(got, test.also)) {
				t.Fatalf("finding = %#v, missing %q %q", matched[0], test.contain, test.also)
			}
		})
	}
}

func TestLintIPSetMembersCleanAndMixed(t *testing.T) {
	t.Parallel()
	clean := &tailscale.ACL{
		Hosts: map[string]string{"gw": "10.10.20.1", "link": "fe80::1%eth0"},
		IPSets: map[string][]string{
			"ipset:p": {"host:gw"},
			"ipset:q": {"10.0.0.0/8", "add ipset:p"},
		},
	}
	for _, id := range newIPSetLintIDs() {
		if got := findingsWithID(t, clean, id); len(got) != 0 {
			t.Fatalf("%s findings = %#v", id, got)
		}
	}
	mixed := &tailscale.ACL{
		IPSets: map[string][]string{"ipset:p": {"remove 10.0.0.0/8", "10.1.0.0/8"}},
	}
	if got := findingsWithID(t, mixed, aclpolicy.LintIPSetMixedOperations); len(got) != 1 {
		t.Fatalf("mixed findings = %#v", got)
	}
	if got := findingsWithID(t, mixed, aclpolicy.LintIPSetMemberInvalid); len(got) != 0 {
		t.Fatalf("invalid findings = %#v", got)
	}
}

func TestLintCatalogAdvertisesIPSetMemberChecks(t *testing.T) {
	t.Parallel()
	for _, id := range newIPSetLintIDs() {
		index := slices.IndexFunc(aclpolicy.LintCatalog(), func(check aclpolicy.LintCheck) bool {
			return check.ID == id
		})
		if index < 0 {
			t.Fatalf("catalog missing %s", id)
		}
		if got := aclpolicy.LintCatalog()[index].Severity; got != aclpolicy.LintError {
			t.Fatalf("%s severity = %s", id, got)
		}
	}
}

func newIPSetLintIDs() []string {
	return []string{
		aclpolicy.LintIPSetMemberInvalid,
		aclpolicy.LintIPSetReferenceUndefined,
		aclpolicy.LintIPSetReferenceCycle,
		aclpolicy.LintHostNotAddress,
	}
}

func findingsWithID(t *testing.T, policy *tailscale.ACL, id string) []aclpolicy.LintFinding {
	t.Helper()
	report, err := aclpolicy.EvaluateLint(policy, aclpolicy.LintOptions{})
	if err != nil {
		t.Fatal(err)
	}
	var matched []aclpolicy.LintFinding
	for _, finding := range report.Findings {
		if finding.ID == id {
			matched = append(matched, finding)
		}
	}
	return matched
}
