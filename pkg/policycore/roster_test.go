package policycore_test

import (
	"maps"
	"strings"
	"testing"

	tailscale "tailscale.com/client/tailscale/v2"

	"github.com/rshade/tsacl/pkg/policycore"
)

func TestParseRosterAcceptsBothFormats(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		data string
		want map[string]tailscale.UserRole
	}{
		{
			name: "flat map",
			data: `{"ada@example.com": "admin", "joe@example.com": "member"}`,
			want: map[string]tailscale.UserRole{
				"ada@example.com": tailscale.UserRoleAdmin,
				"joe@example.com": tailscale.UserRoleMember,
			},
		},
		{
			name: "api envelope ignores extra fields",
			data: `{"users":[
				{"loginName":"ada@example.com","role":"admin","id":"u1","deviceCount":3},
				{"loginName":"joe@example.com","role":"member"}
			]}`,
			want: map[string]tailscale.UserRole{
				"ada@example.com": tailscale.UserRoleAdmin,
				"joe@example.com": tailscale.UserRoleMember,
			},
		},
		{
			name: "logins are lowercased in both formats",
			data: `{"Ada@Example.COM": "auditor"}`,
			want: map[string]tailscale.UserRole{"ada@example.com": tailscale.UserRoleAuditor},
		},
		{
			name: "envelope logins are lowercased too",
			data: `{"users":[{"loginName":"Ada@Example.COM","role":"owner"}]}`,
			want: map[string]tailscale.UserRole{"ada@example.com": tailscale.UserRoleOwner},
		},
		{
			name: "a users key whose value is a role string is a flat-map login",
			data: `{"users": "admin"}`,
			want: map[string]tailscale.UserRole{"users": tailscale.UserRoleAdmin},
		},
		{
			name: "empty flat map asserts a read roster with nobody in it",
			data: `{}`,
			want: map[string]tailscale.UserRole{},
		},
		{
			name: "empty envelope asserts the same",
			data: `{"users":[]}`,
			want: map[string]tailscale.UserRole{},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got, err := policycore.ParseRoster([]byte(test.data))
			if err != nil {
				t.Fatalf("ParseRoster(%s): %v", test.data, err)
			}
			if got == nil {
				t.Fatal("ParseRoster returned a nil map; nil means \"no roster\" to callers")
			}
			if !maps.Equal(got, test.want) {
				t.Errorf("ParseRoster(%s) = %v, want %v", test.data, got, test.want)
			}
		})
	}
}

func TestParseRosterAcceptsEveryTailnetRole(t *testing.T) {
	t.Parallel()
	// Hand-written on purpose: this is the AX convention 13 Tier-2 provenance
	// guard for the role vocabulary. A guard that reads its expectations from
	// the descriptor it guards proves nothing, so this list must never be
	// generated from policycore's own internals.
	roles := []tailscale.UserRole{
		tailscale.UserRoleOwner,
		tailscale.UserRoleMember,
		tailscale.UserRoleAdmin,
		tailscale.UserRoleITAdmin,
		tailscale.UserRoleNetworkAdmin,
		tailscale.UserRoleBillingAdmin,
		tailscale.UserRoleAuditor,
	}
	for _, role := range roles {
		t.Run(string(role), func(t *testing.T) {
			t.Parallel()
			data := []byte(`{"ada@example.com": "` + string(role) + `"}`)
			got, err := policycore.ParseRoster(data)
			if err != nil {
				t.Fatalf("ParseRoster rejected the pinned role %q: %v", role, err)
			}
			if got["ada@example.com"] != role {
				t.Errorf("role %q round-tripped as %q", role, got["ada@example.com"])
			}
		})
	}
}

func TestParseRosterRejectsEveryDefectLoudly(t *testing.T) {
	t.Parallel()
	// Every entry here is a defect that would otherwise become a confident
	// wrong answer: with HaveRoles true, a dropped or mis-keyed entry is
	// indistinguishable from a login the roster deliberately does not list,
	// and absence means a definite NoMatch.
	tests := []struct {
		name     string
		data     string
		contains string
	}{
		{
			name:     "unparseable json",
			data:     `{"ada@example.com": }`,
			contains: "invalid JSON at offset",
		},
		{
			name:     "unknown role in the flat form",
			data:     `{"ada@example.com": "adminn"}`,
			contains: `unknown role "adminn"`,
		},
		{
			name:     "unknown role in the envelope form",
			data:     `{"users":[{"loginName":"ada@example.com","role":"superuser"}]}`,
			contains: `unknown role "superuser"`,
		},
		{
			name:     "the error names the allowed vocabulary",
			data:     `{"ada@example.com": "adminn"}`,
			contains: "want owner, member, admin, it-admin, network-admin, billing-admin, or auditor",
		},
		{
			name:     "duplicate login after lowercasing",
			data:     `{"Ada@example.com": "admin", "ada@example.com": "member"}`,
			contains: "appears twice",
		},
		{
			name:     "duplicate names both spellings",
			data:     `{"Ada@example.com": "admin", "ada@example.com": "member"}`,
			contains: `(as "Ada@example.com" and "ada@example.com")`,
		},
		{
			name:     "empty login in the envelope form",
			data:     `{"users":[{"loginName":"","role":"admin"}]}`,
			contains: "empty login name",
		},
		{
			name:     "whitespace-only login is empty too",
			data:     `{"   ": "admin"}`,
			contains: "empty login name",
		},
		{
			name:     "non-string role",
			data:     `{"ada@example.com": 7}`,
			contains: "non-string role",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			roster, err := policycore.ParseRoster([]byte(test.data))
			if err == nil {
				t.Fatalf("ParseRoster(%s) succeeded with %v; want an error", test.data, roster)
			}
			if roster != nil {
				t.Errorf("ParseRoster returned %v alongside an error; want nil", roster)
			}
			if !strings.Contains(err.Error(), test.contains) {
				t.Errorf("ParseRoster(%s) = %q, want it to contain %q", test.data, err, test.contains)
			}
		})
	}
}

func TestParseRosterReportsTheSameDefectEveryRun(t *testing.T) {
	t.Parallel()
	// Map iteration is randomised. Without a deterministic walk order a file
	// carrying several defects reports a different one per run, which is both a
	// flaky test and an irreproducible error for the operator.
	//
	// Three defects and 200 rounds, not two and 20, because "randomised" is not
	// "uniformly shuffled": Go randomises the starting bucket, so a two-key map
	// skews heavily toward one order — measured at roughly 87/13, which left the
	// original shape passing about one run in sixteen with the sort removed. A
	// third key and a longer loop drive that to nil while still costing under a
	// millisecond.
	data := []byte(`{
		"zoe@example.com": "nope",
		"amy@example.com": "bogus",
		"kim@example.com": "wrong"
	}`)
	first, err := policycore.ParseRoster(data)
	if err == nil {
		t.Fatalf("ParseRoster succeeded with %v; want an error", first)
	}
	for range 200 {
		_, again := policycore.ParseRoster(data)
		if again == nil || again.Error() != err.Error() {
			t.Fatalf("ParseRoster reported %v then %v; want one stable message", err, again)
		}
	}
}
