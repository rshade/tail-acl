package policycore_test

import (
	"testing"

	"github.com/rshade/tailscale-utils/policycore"

	tailscale "tailscale.com/client/tailscale/v2"
)

func TestSelectorMatches(t *testing.T) {
	t.Parallel()

	policy := &tailscale.ACL{
		Groups: map[string][]string{
			"group:eng":   {"alice@example.com", "group:ops"},
			"group:ops":   {"bob@example.com"},
			"group:cycle": {"group:cycle"},
		},
		Hosts: map[string]string{"web": "10.1.0.0/16"},
	}
	tests := []struct {
		name     string
		selector string
		query    string
		source   string
		want     bool
	}{
		{name: "wildcard matches anything", selector: "*", query: "tag:web", want: true},
		{name: "exact tag match", selector: "tag:web", query: "tag:web", want: true},
		{name: "different tag", selector: "tag:web", query: "tag:db", want: false},
		{name: "direct group member", selector: "group:eng", query: "alice@example.com", want: true},
		{name: "nested group member", selector: "group:eng", query: "bob@example.com", want: true},
		{name: "non member", selector: "group:eng", query: "eve@example.com", want: false},
		{name: "cyclic group terminates", selector: "group:cycle", query: "eve@example.com", want: false},
		{name: "autogroup:member matches user", selector: "autogroup:member", query: "alice@example.com", want: true},
		{name: "autogroup:member ignores tag", selector: "autogroup:member", query: "tag:web", want: false},
		{
			name:     "autogroup:self matches source user",
			selector: "autogroup:self",
			query:    "alice@example.com",
			source:   "alice@example.com",
			want:     true,
		},
		{
			name:     "autogroup:self rejects other user",
			selector: "autogroup:self",
			query:    "alice@example.com",
			source:   "bob@example.com",
			want:     false,
		},
		{
			name:     "autogroup:internet matches public address",
			selector: "autogroup:internet",
			query:    "8.8.8.8",
			want:     true,
		},
		{
			name:     "autogroup:internet rejects private address",
			selector: "autogroup:internet",
			query:    "10.1.2.3",
			want:     false,
		},
		{
			name:     "autogroup:tagged matches a tagged device",
			selector: "autogroup:tagged",
			query:    "tag:web",
			want:     true,
		},
		{
			name:     "autogroup:tagged rejects a user",
			selector: "autogroup:tagged",
			query:    "alice@example.com",
			want:     false,
		},
		{name: "host selector contains address", selector: "web", query: "10.1.2.3", want: true},
		{name: "host selector excludes outside address", selector: "web", query: "10.9.2.3", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			matcher := policycore.Matcher{Policy: policy}
			got := matcher.Matches(tt.selector, tt.query, tt.source)
			if got != tt.want {
				t.Errorf("Matches(%q, %q) = %v; want %v", tt.selector, tt.query, got, tt.want)
			}
		})
	}
}

func TestAnyMatches(t *testing.T) {
	t.Parallel()

	matcher := policycore.Matcher{Policy: &tailscale.ACL{}}
	if !matcher.AnyMatches([]string{"tag:db", "tag:web"}, "tag:web", "") {
		t.Error("AnyMatches: want true when one selector matches")
	}
	if matcher.AnyMatches([]string{"tag:db"}, "tag:web", "") {
		t.Error("AnyMatches: want false when no selector matches")
	}
	if matcher.AnyMatches(nil, "tag:web", "") {
		t.Error("AnyMatches(nil): want false")
	}
}

func TestLooksLikeUser(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		value string
		want  bool
	}{
		{name: "email is a user", value: "alice@example.com", want: true},
		{name: "group is not a user", value: "group:eng@example.com", want: false},
		{name: "tag is not a user", value: "tag:web", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := policycore.LooksLikeUser(tt.value); got != tt.want {
				t.Errorf("LooksLikeUser(%q) = %v; want %v", tt.value, got, tt.want)
			}
		})
	}
}

func TestMatcherResolvesRoleAutogroups(t *testing.T) {
	t.Parallel()

	roles := map[string]tailscale.UserRole{
		"ada@example.com":  tailscale.UserRoleAdmin,
		"root@example.com": tailscale.UserRoleOwner,
		"nic@example.com":  tailscale.UserRoleNetworkAdmin,
		"ida@example.com":  tailscale.UserRoleITAdmin,
		"bil@example.com":  tailscale.UserRoleBillingAdmin,
		"aud@example.com":  tailscale.UserRoleAuditor,
		"joe@example.com":  tailscale.UserRoleMember,
	}
	matcher := policycore.Matcher{Policy: &tailscale.ACL{}, Roles: roles, HaveRoles: true}
	tests := []struct {
		name     string
		selector string
		query    string
		want     bool
	}{
		{name: "admin matches admin", selector: "autogroup:admin", query: "ada@example.com", want: true},
		{name: "admin ignores member", selector: "autogroup:admin", query: "joe@example.com", want: false},
		{name: "admin is not owner", selector: "autogroup:admin", query: "root@example.com", want: false},
		{name: "owner is not admin", selector: "autogroup:owner", query: "ada@example.com", want: false},
		{name: "owner matches owner", selector: "autogroup:owner", query: "root@example.com", want: true},
		{name: "network admin", selector: "autogroup:network-admin", query: "nic@example.com", want: true},
		{name: "it admin", selector: "autogroup:it-admin", query: "ida@example.com", want: true},
		{name: "billing admin", selector: "autogroup:billing-admin", query: "bil@example.com", want: true},
		{name: "auditor", selector: "autogroup:auditor", query: "aud@example.com", want: true},
		{name: "login case is ignored", selector: "autogroup:admin", query: "ADA@Example.com", want: true},
		{name: "unknown login", selector: "autogroup:admin", query: "eve@example.com", want: false},
		{name: "tag never matches a role", selector: "autogroup:admin", query: "tag:web", want: false},
		{name: "address never matches a role", selector: "autogroup:admin", query: "100.64.0.1", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := matcher.Matches(tt.selector, tt.query, tt.query); got != tt.want {
				t.Errorf("Matches(%q, %q) = %v; want %v", tt.selector, tt.query, got, tt.want)
			}
		})
	}
}

func TestMatcherMatchesTriRoleAutogroupMatrix(t *testing.T) {
	t.Parallel()

	roles := map[string]tailscale.UserRole{
		"ada@example.com": tailscale.UserRoleAdmin,
		"joe@example.com": tailscale.UserRoleMember,
	}
	tests := []struct {
		name      string
		haveRoles bool
		query     string
		want      policycore.Match
	}{
		{
			name:  "no roster tag is a decidable non-match",
			query: "tag:web",
			want:  policycore.NoMatch,
		},
		{
			name:  "no roster user is unresolvable",
			query: "ada@example.com",
			want:  policycore.Unresolvable,
		},
		{
			name:  "no roster bare device is unresolvable",
			query: "100.64.0.9",
			want:  policycore.Unresolvable,
		},
		{
			name:      "roster tag is a decidable non-match",
			haveRoles: true,
			query:     "tag:web",
			want:      policycore.NoMatch,
		},
		{
			name:      "roster user with matching role matches",
			haveRoles: true,
			query:     "ada@example.com",
			want:      policycore.Matched,
		},
		{
			name:      "roster user with another role does not match",
			haveRoles: true,
			query:     "joe@example.com",
			want:      policycore.NoMatch,
		},
		{
			name:      "user absent from complete roster does not match",
			haveRoles: true,
			query:     "eve@example.com",
			want:      policycore.NoMatch,
		},
		{
			name:      "roster never settles a bare device",
			haveRoles: true,
			query:     "100.64.0.9",
			want:      policycore.Unresolvable,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			matcher := policycore.Matcher{
				Policy:    &tailscale.ACL{},
				Roles:     roles,
				HaveRoles: test.haveRoles,
			}
			if got := matcher.MatchesTri(
				"autogroup:admin", test.query, "",
			); got != test.want {
				t.Errorf("MatchesTri(autogroup:admin, %q) = %v; want %v", test.query, got, test.want)
			}
		})
	}
}

func TestMatcherWithoutRolesResolvesNoRoleAutogroup(t *testing.T) {
	t.Parallel()

	matcher := policycore.Matcher{Policy: &tailscale.ACL{}}
	for _, selector := range roleAutogroupSelectors() {
		t.Run(selector, func(t *testing.T) {
			t.Parallel()

			if matcher.Matches(selector, "ada@example.com", "ada@example.com") {
				t.Errorf("Matches(%q) = true with no role data; want false", selector)
			}
			if matcher.Recognized(selector) {
				t.Errorf("Recognized(%q) = true with no role data; want false", selector)
			}
		})
	}
}

// TestRecognizedTracksRoleResolution is the anti-drift guard: every selector
// IsRoleAutogroup claims must become recognized exactly when role data is
// present, and Recognized must agree with MatchesTri about whether a role
// autogroup is decidable against a user. That keeps the set the package resolves
// and the set it says it understands from diverging.
func TestRecognizedTracksRoleResolution(t *testing.T) {
	t.Parallel()

	withoutRoles := policycore.Matcher{Policy: &tailscale.ACL{}}
	withRoles := policycore.Matcher{
		Policy:    &tailscale.ACL{},
		Roles:     map[string]tailscale.UserRole{"ada@example.com": tailscale.UserRoleAdmin},
		HaveRoles: true,
	}
	for _, selector := range roleAutogroupSelectors() {
		t.Run(selector, func(t *testing.T) {
			t.Parallel()

			if !policycore.IsRoleAutogroup(selector) {
				t.Fatalf("IsRoleAutogroup(%q) = false; want true", selector)
			}
			if !withRoles.Recognized(selector) {
				t.Errorf("Recognized(%q) = false with role data; want true", selector)
			}
			for name, matcher := range map[string]policycore.Matcher{
				"without role data": withoutRoles,
				"with role data":    withRoles,
			} {
				decidable := matcher.MatchesTri(
					selector, "ada@example.com", "",
				) != policycore.Unresolvable
				if matcher.Recognized(selector) != decidable {
					t.Errorf(
						"%s: Recognized(%q) = %v but MatchesTri decidable = %v",
						name,
						selector,
						matcher.Recognized(selector),
						decidable,
					)
				}
			}
		})
	}
}

func TestMatcherRecognizesRoleAutogroupsWithEmptyRoster(t *testing.T) {
	t.Parallel()

	matcher := policycore.Matcher{
		Policy:    &tailscale.ACL{},
		Roles:     map[string]tailscale.UserRole{},
		HaveRoles: true,
	}
	for _, selector := range roleAutogroupSelectors() {
		t.Run(selector, func(t *testing.T) {
			t.Parallel()

			if !matcher.Recognized(selector) {
				t.Errorf("Recognized(%q) = false after an empty roster was read; want true", selector)
			}
			if matcher.Matches(selector, "ada@example.com", "ada@example.com") {
				t.Errorf("Matches(%q) = true with an empty roster; want false", selector)
			}
			if got := matcher.MatchesTri(
				selector, "ada@example.com", "ada@example.com",
			); got != policycore.NoMatch {
				t.Errorf("MatchesTri(%q) = %v with an empty roster; want NoMatch", selector, got)
			}
		})
	}
}

func TestMatcherIgnoresRolesWithoutRosterAvailability(t *testing.T) {
	t.Parallel()

	matcher := policycore.Matcher{
		Policy: &tailscale.ACL{},
		Roles:  map[string]tailscale.UserRole{"ada@example.com": tailscale.UserRoleAdmin},
	}
	if matcher.Recognized("autogroup:admin") {
		t.Error("Recognized(autogroup:admin) = true without roster availability; want false")
	}
	if matcher.Matches("autogroup:admin", "ada@example.com", "ada@example.com") {
		t.Error("Matches(autogroup:admin) = true without roster availability; want false")
	}
	if got := matcher.MatchesTri(
		"autogroup:admin", "ada@example.com", "ada@example.com",
	); got != policycore.Unresolvable {
		t.Errorf("MatchesTri(autogroup:admin) = %v without roster availability; want Unresolvable", got)
	}
}

func TestRecognized(t *testing.T) {
	t.Parallel()

	matcher := policycore.Matcher{Policy: &tailscale.ACL{}}
	tests := []struct {
		name     string
		selector string
		want     bool
	}{
		{name: "plain tag", selector: "tag:web", want: true},
		{name: "user", selector: "ada@example.com", want: true},
		{name: "group", selector: "group:eng", want: true},
		{name: "wildcard", selector: "*", want: true},
		{name: "address", selector: "100.64.0.0/10", want: true},
		{name: "autogroup:self", selector: "autogroup:self", want: true},
		{name: "autogroup:member", selector: "autogroup:member", want: true},
		{name: "autogroup:members", selector: "autogroup:members", want: true},
		{name: "autogroup:tagged", selector: "autogroup:tagged", want: true},
		{name: "autogroup:internet", selector: "autogroup:internet", want: true},
		{name: "autogroup:shared", selector: "autogroup:shared", want: false},
		// danger-all matches every device, so it is resolved rather than
		// undecidable: a grant using it is wide open, and reporting it
		// unresolved would claim coverage might be understated for a selector
		// that covers everything.
		{name: "autogroup:danger-all", selector: "autogroup:danger-all", want: true},
		{name: "autogroup:nonroot", selector: "autogroup:nonroot", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := matcher.Recognized(tt.selector); got != tt.want {
				t.Errorf("Recognized(%q) = %v; want %v", tt.selector, got, tt.want)
			}
		})
	}
}

// roleAutogroupSelectors lists every role autogroup the package resolves. It is
// a test-local literal on purpose: an independent restatement of the set is what
// makes the anti-drift tests meaningful.
func roleAutogroupSelectors() []string {
	return []string{
		"autogroup:owner",
		"autogroup:admin",
		"autogroup:it-admin",
		"autogroup:network-admin",
		"autogroup:billing-admin",
		"autogroup:auditor",
	}
}
