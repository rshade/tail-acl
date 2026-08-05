package aclpolicy_test

import (
	"path/filepath"
	"strings"
	"testing"

	tailscale "tailscale.com/client/tailscale/v2"

	"github.com/rshade/tailscale-utils/tail-acl/internal/aclpolicy"
)

// loadReachabilityPolicy returns the fixture whose grant 4 is gated on
// autogroup:admin, which is the branch a roster is meant to settle.
func loadReachabilityPolicy(t *testing.T) *aclpolicy.Policy {
	t.Helper()
	policy, err := aclpolicy.Load(filepath.Join("testdata", "reachability_policy.hujson"))
	if err != nil {
		t.Fatal(err)
	}
	return policy
}

func TestRosterSettlesRoleAutogroups(t *testing.T) {
	t.Parallel()
	policy := loadReachabilityPolicy(t)
	tests := []struct {
		name   string
		source string
		roster map[string]tailscale.UserRole
		want   aclpolicy.Access
	}{
		{
			name:   "no roster leaves the question open",
			source: "alice@example.com",
			roster: nil,
			want:   aclpolicy.AccessIndeterminate,
		},
		{
			name:   "a roster naming the login as admin settles it",
			source: "alice@example.com",
			roster: map[string]tailscale.UserRole{"alice@example.com": tailscale.UserRoleAdmin},
			want:   aclpolicy.AccessAllow,
		},
		{
			name:   "a roster naming the login as a plain member settles it the other way",
			source: "alice@example.com",
			roster: map[string]tailscale.UserRole{"alice@example.com": tailscale.UserRoleMember},
			want:   aclpolicy.AccessDeny,
		},
		{
			// The complete roster was read and nobody holds a role. That is a
			// definite answer, not an unread roster, and must not collapse back
			// into indeterminate.
			name:   "an empty but non-nil roster is a read roster with nobody in it",
			source: "alice@example.com",
			roster: map[string]tailscale.UserRole{},
			want:   aclpolicy.AccessDeny,
		},
		{
			// The query is deliberately spelled differently from the roster key.
			// roleMatches lowercases the query before the lookup because
			// Device.User and User.LoginName are not guaranteed to agree on
			// case; roster keys are lowercased upstream by ParseRoster, which
			// this test bypasses by building the map directly. So the mixed
			// case must live on the query — with both sides lowercase this case
			// would be an exact duplicate of the admin case above and would
			// still pass with strings.ToLower removed from roleMatches
			// entirely, proving nothing.
			name:   "a differently-cased login still resolves",
			source: "Alice@Example.COM",
			roster: map[string]tailscale.UserRole{"alice@example.com": tailscale.UserRoleAdmin},
			want:   aclpolicy.AccessAllow,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			decision, err := aclpolicy.EvaluateReachability(
				&policy.ACL,
				test.source,
				"tag:audit:8443",
				aclpolicy.ReachabilityOptions{Roster: test.roster},
			)
			if err != nil {
				t.Fatal(err)
			}
			if decision.Access != test.want {
				t.Errorf("access = %q, want %q (evidence: %s)",
					decision.Access, test.want, decision.Evidence)
			}
		})
	}
}

func TestRosterCannotIdentifyADeviceOwner(t *testing.T) {
	t.Parallel()
	// A roster maps logins to roles. It says nothing about whose device an
	// address is, so a bare device source against a role autogroup stays
	// indeterminate even with a complete roster in hand. Reporting a verdict
	// here would be a confident wrong answer.
	//
	// This guards policycore's device-vs-role gate, not this package's roster
	// wiring: settlesRole is false for a bare device whatever haveRoles says,
	// so this test would still pass if Roster were dropped on the floor here.
	// TestRosterSettlesRoleAutogroups is what proves the wiring.
	policy := loadReachabilityPolicy(t)
	decision, err := aclpolicy.EvaluateReachability(
		&policy.ACL,
		"100.64.0.9",
		"tag:audit:8443",
		aclpolicy.ReachabilityOptions{
			Roster: map[string]tailscale.UserRole{"alice@example.com": tailscale.UserRoleAdmin},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Access != aclpolicy.AccessIndeterminate {
		t.Errorf("access = %q, want %q", decision.Access, aclpolicy.AccessIndeterminate)
	}
}

func TestIndeterminateEvidenceSaysWhatWouldSettleIt(t *testing.T) {
	t.Parallel()
	// An unresolved role autogroup has two operator-facing causes and they need
	// opposite advice. Telling someone to supply the roster they already
	// supplied is the worst possible message, so the two must not share wording.
	policy := loadReachabilityPolicy(t)
	tests := []struct {
		name     string
		source   string
		roster   map[string]tailscale.UserRole
		contains string
		absent   string
	}{
		{
			name:     "no roster names the flag that would settle it",
			source:   "alice@example.com",
			roster:   nil,
			contains: "supply --roster PATH",
		},
		{
			name:     "a bare device says why a roster cannot help",
			source:   "100.64.0.9",
			roster:   map[string]tailscale.UserRole{"alice@example.com": tailscale.UserRoleAdmin},
			contains: "cannot identify a device's owner",
			absent:   "supply --roster PATH",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			decision, err := aclpolicy.EvaluateReachability(
				&policy.ACL, test.source, "tag:audit:8443",
				aclpolicy.ReachabilityOptions{Roster: test.roster},
			)
			if err != nil {
				t.Fatal(err)
			}
			if decision.Access != aclpolicy.AccessIndeterminate {
				t.Fatalf("access = %q, want indeterminate", decision.Access)
			}
			if !strings.Contains(decision.Evidence, test.contains) {
				t.Errorf("evidence = %q, want it to contain %q", decision.Evidence, test.contains)
			}
			if test.absent != "" && strings.Contains(decision.Evidence, test.absent) {
				t.Errorf("evidence = %q, want it NOT to contain %q", decision.Evidence, test.absent)
			}
		})
	}
}

func TestNonRoleSelectorKeepsItsOriginalWording(t *testing.T) {
	t.Parallel()
	// Only role autogroups gained new advice. A selector undecidable for any
	// other reason must read exactly as it always has, or the change is a
	// behavioural one wearing a message's clothes.
	//
	// This deliberately does NOT use the shared reachability fixture. Every
	// unresolvable selector in that file is autogroup:admin — a role autogroup —
	// so a test written against it would exercise the roster-hint branch instead
	// and pass merely because that message contains the original clause as a
	// prefix, staying green even if the non-role wording changed. autogroup:shared
	// is absent from policycore's autogroup vocabulary, so it is unresolvable and
	// not a role, which is the combination this branch needs.
	policy := grantPolicy(tailscale.Grant{
		Source:      []string{"autogroup:shared"},
		Destination: []string{"tag:web"},
		IP:          []string{"tcp:443"},
	})
	decision := evaluate(t, policy, "alice@example.com", "tag:web:443", aclpolicy.ReachabilityOptions{})
	if decision.Access != aclpolicy.AccessIndeterminate {
		t.Fatalf("access = %q, want indeterminate (evidence: %s)", decision.Access, decision.Evidence)
	}
	if !strings.Contains(decision.Evidence, "cannot be resolved from the policy file") {
		t.Errorf("evidence = %q, want the original clause preserved", decision.Evidence)
	}
	// The real assertion: neither role-autogroup remedy may leak onto a
	// selector that is not a role autogroup.
	for _, unwanted := range []string{"supply --roster PATH", "cannot identify a device's owner"} {
		if strings.Contains(decision.Evidence, unwanted) {
			t.Errorf("evidence = %q, want it NOT to contain %q", decision.Evidence, unwanted)
		}
	}
}
