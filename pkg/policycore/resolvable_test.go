package policycore_test

import (
	"testing"

	tailscale "tailscale.com/client/tailscale/v2"

	"github.com/rshade/tailscale-utils/policycore"
)

func TestAutogroupResolvableDependsOnTheQueryNotTheSelectorAlone(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		selector string
		query    string
		want     bool
	}{
		{"plain selector is always decidable", "alice@example.com", "100.64.0.9", true},
		{"tag selector is always decidable", "tag:web", "100.64.0.9", true},

		{"danger-all matches everything", "autogroup:danger-all", "100.64.0.9", true},
		{"internet is address arithmetic", "autogroup:internet", "100.64.0.9", true},

		{"self settles against a user", "autogroup:self", "alice@example.com", true},
		{"self needs the owner for a device", "autogroup:self", "100.64.0.9", false},

		{"tagged settles against a tag", "autogroup:tagged", "tag:web", true},
		{"tagged settles against a user", "autogroup:tagged", "alice@example.com", true},
		{"tagged needs the tag map for a device", "autogroup:tagged", "100.64.0.9", false},
		{"member settles against a user", "autogroup:member", "alice@example.com", true},
		{"member needs the tag map for a device", "autogroup:members", "100.64.0.9", false},

		// A tagged device has no user owner, so a tag refutes a role autogroup
		// with certainty; anything else needs the control plane's role map.
		{"admin is refuted by a tag", "autogroup:admin", "tag:web", true},
		{"admin is undecidable against a user", "autogroup:admin", "alice@example.com", false},
		{"admin is undecidable against a device", "autogroup:admin", "100.64.0.9", false},
		{"auditor is refuted by a tag", "autogroup:auditor", "tag:web", true},
		{"network-admin is undecidable against a user", "autogroup:network-admin", "alice@example.com", false},

		{"shared is undecidable against a tag", "autogroup:shared", "tag:web", false},
		{"an unknown autogroup is undecidable", "autogroup:invented-later", "tag:web", false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := policycore.AutogroupResolvable(test.selector, test.query); got != test.want {
				t.Errorf("AutogroupResolvable(%q, %q) = %v, want %v",
					test.selector, test.query, got, test.want)
			}
		})
	}
}

func TestSelectorMatchesTriSeparatesNoMatchFromUnresolvable(t *testing.T) {
	t.Parallel()
	policy := &tailscale.ACL{}
	tests := []struct {
		name     string
		selector string
		query    string
		want     policycore.Match
	}{
		{"exact match", "tag:web", "tag:web", policycore.Matched},
		{"wildcard matches", "*", "100.64.0.9", policycore.Matched},
		{"danger-all matches", "autogroup:danger-all", "100.64.0.9", policycore.Matched},
		{"provable non-match", "tag:web", "tag:db", policycore.NoMatch},
		{"role autogroup refuted by a tag", "autogroup:admin", "tag:web", policycore.NoMatch},
		{
			"role autogroup against a user is unresolvable",
			"autogroup:admin", "alice@example.com", policycore.Unresolvable,
		},
		{
			"tagged against a bare device is unresolvable",
			"autogroup:tagged", "100.64.0.9", policycore.Unresolvable,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got := policycore.SelectorMatchesTri(test.selector, test.query, policy, "alice@example.com")
			if got != test.want {
				t.Errorf("SelectorMatchesTri(%q, %q) = %v, want %v",
					test.selector, test.query, got, test.want)
			}
		})
	}
}

func TestSelectorMatchesTriPropagatesGroupUndecidability(t *testing.T) {
	t.Parallel()

	policy := &tailscale.ACL{
		Groups: map[string][]string{
			"group:tagged":        {"autogroup:tagged"},
			"group:decidable":     {"alice@example.com", "tag:web"},
			"group:match-wins":    {"autogroup:tagged", "100.64.0.9"},
			"group:a":             {"group:b"},
			"group:b":             {"autogroup:self"},
			"group:cycle":         {"group:cycle"},
			"group:cycle-unknown": {"group:cycle-unknown", "autogroup:tagged"},
			"group:diamond":       {"group:left", "group:right"},
			"group:left":          {"group:shared"},
			"group:right":         {"group:shared"},
			"group:shared":        {"autogroup:tagged"},
			"unprefixed":          {"autogroup:tagged"},
			"autogroup:admin":     {"alice@example.com"},
		},
	}
	tests := []struct {
		name     string
		selector string
		query    string
		want     policycore.Match
	}{
		{
			name:     "nested tagged autogroup needs device tag map",
			selector: "group:tagged", query: "100.64.0.9",
			want: policycore.Unresolvable,
		},
		{
			name:     "nested tagged autogroup settles against tag",
			selector: "group:tagged", query: "tag:db",
			want: policycore.Matched,
		},
		{
			name:     "group with decidable members keeps definite verdict",
			selector: "group:decidable", query: "tag:db",
			want: policycore.NoMatch,
		},
		{
			name:     "definite member match outranks nested undecidability",
			selector: "group:match-wins", query: "100.64.0.9",
			want: policycore.Matched,
		},
		{
			name:     "undecidability propagates through two group levels",
			selector: "group:a", query: "100.64.0.9",
			want: policycore.Unresolvable,
		},
		{
			name:     "self cycle terminates as a definite non-match",
			selector: "group:cycle", query: "eve@example.com",
			want: policycore.NoMatch,
		},
		{
			name:     "cycle still propagates another undecidable member",
			selector: "group:cycle-unknown", query: "100.64.0.9",
			want: policycore.Unresolvable,
		},
		{
			name:     "diamond terminates and propagates shared undecidability",
			selector: "group:diamond", query: "100.64.0.9",
			want: policycore.Unresolvable,
		},
		{
			name:     "undefined group remains a definite non-match",
			selector: "group:missing", query: "100.64.0.9",
			want: policycore.NoMatch,
		},
		{
			// Membership is keyed on the selector, not on the group: prefix, so a
			// groups entry the control plane would reject is still expanded by
			// Matches. Reporting it settled here would be a confident wrong deny
			// on exactly the unvalidated candidate file this evaluator exists for.
			name:     "group key without the group: prefix still propagates",
			selector: "unprefixed", query: "100.64.0.9",
			want: policycore.Unresolvable,
		},
		{
			// Matches names this selector through both readings, so a decidable
			// member list must not settle the roster-dependent autogroup reading.
			name:     "groups key shadowing an autogroup keeps the autogroup undecidable",
			selector: "autogroup:admin", query: "bob@example.com",
			want: policycore.Unresolvable,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got := policycore.SelectorMatchesTri(test.selector, test.query, policy, "")
			if got != test.want {
				t.Errorf(
					"SelectorMatchesTri(%q, %q) = %v, want %v",
					test.selector,
					test.query,
					got,
					test.want,
				)
			}
		})
	}
}

// The group recursion must keep the zero-value Matcher behind AutogroupResolvable
// safe: it holds no Policy, so the membership lookup has to report "names no
// groups" rather than dereference one. This covers only the roster-blind entry
// point; MatchesTri still requires a non-nil Policy, because address expansion
// dereferences it well before groups are consulted.
func TestAutogroupResolvableWalksGroupSelectorsWithoutAPolicy(t *testing.T) {
	t.Parallel()

	if !policycore.AutogroupResolvable("group:eng", "100.64.0.9") {
		t.Error("AutogroupResolvable(group:eng) with no policy = false; want true")
	}
}

func TestMatcherMatchesTriUsesRosterInsideGroups(t *testing.T) {
	t.Parallel()

	policy := &tailscale.ACL{
		Groups: map[string][]string{
			"group:admins": {"autogroup:admin"},
		},
	}
	matcher := policycore.Matcher{
		Policy: &policycore.Policy{ACL: policy},
		Roles: map[string]tailscale.UserRole{
			"ada@example.com": tailscale.UserRoleAdmin,
			"joe@example.com": tailscale.UserRoleMember,
		},
		HaveRoles: true,
	}
	for _, test := range []struct {
		query string
		want  policycore.Match
	}{
		{query: "ada@example.com", want: policycore.Matched},
		{query: "joe@example.com", want: policycore.NoMatch},
		{query: "100.64.0.9", want: policycore.Unresolvable},
	} {
		if got := matcher.MatchesTri("group:admins", test.query, ""); got != test.want {
			t.Errorf("MatchesTri(group:admins, %q) = %v, want %v", test.query, got, test.want)
		}
	}
}

func TestAnySelectorMatchesTriLetsAMatchOutrankAnEarlierUnresolvable(t *testing.T) {
	t.Parallel()
	policy := &tailscale.ACL{}

	// The unresolvable selector comes first, but a later definite match settles
	// the list: an allow is an allow no matter what else could not be decided.
	match, unresolved := policycore.AnySelectorMatchesTri(
		[]string{"autogroup:admin", "tag:web"}, "tag:web", policy, "alice@example.com")
	if match != policycore.Matched || unresolved != "" {
		t.Errorf("got (%v, %q), want (Matched, \"\")", match, unresolved)
	}
}

func TestAnySelectorMatchesTriReportsTheFirstUndecidableSelector(t *testing.T) {
	t.Parallel()
	policy := &tailscale.ACL{}

	match, unresolved := policycore.AnySelectorMatchesTri(
		[]string{"tag:db", "autogroup:admin", "autogroup:shared"},
		"alice@example.com", policy, "bob@example.com")
	if match != policycore.Unresolvable || unresolved != "autogroup:admin" {
		t.Errorf("got (%v, %q), want (Unresolvable, \"autogroup:admin\")", match, unresolved)
	}
}

func TestAnySelectorMatchesTriReportsNoMatchWhenEverySelectorIsDecidable(t *testing.T) {
	t.Parallel()
	policy := &tailscale.ACL{}

	match, unresolved := policycore.AnySelectorMatchesTri(
		[]string{"tag:db", "alice@example.com"}, "tag:web", policy, "alice@example.com")
	if match != policycore.NoMatch || unresolved != "" {
		t.Errorf("got (%v, %q), want (NoMatch, \"\")", match, unresolved)
	}
}

func TestKnownAutogroupExcludesRolesAndTracksTheMatchableSet(t *testing.T) {
	t.Parallel()
	known := []string{
		"autogroup:self", "autogroup:member", "autogroup:members",
		"autogroup:tagged", "autogroup:internet", "autogroup:danger-all",
	}
	for _, selector := range known {
		if !policycore.KnownAutogroup(selector) {
			t.Errorf("KnownAutogroup(%q) = false, want true", selector)
		}
	}
	// Roles are refutable but never confirmable offline, so a policy-level
	// grader must keep treating them as a caveat.
	unknown := []string{
		"autogroup:admin", "autogroup:owner", "autogroup:auditor",
		"autogroup:shared", "autogroup:invented-later", "tag:web",
	}
	for _, selector := range unknown {
		if policycore.KnownAutogroup(selector) {
			t.Errorf("KnownAutogroup(%q) = true, want false", selector)
		}
	}
}

// TestKnownAutogroupMatchesResolverParity is the drift guard #34 asks for.
//
// It deliberately does not compare against a list of autogroups — a list is a
// third copy of the same knowledge, and a test that restates what it checks
// cannot detect divergence. Instead it asserts a biconditional over a corpus:
// KnownAutogroup vouches for a selector if and only if the resolver can
// actually match it against some query.
//
// Both directions matter. A selector KnownAutogroup vouches for but the
// resolver never matches is failure mode (b) — the unresolved-selector safety
// valve silently drops it. A selector the resolver matches but KnownAutogroup
// omits is failure mode (a) — a resolved selector reported as unresolved.
//
// This guard deliberately stays roster-blind. KnownAutogroup means confirmable
// without a roster, so comparing it with a roster-bearing Matcher would break
// the biconditional by construction and stop guarding the exported contract.
func TestKnownAutogroupMatchesResolverParity(t *testing.T) {
	t.Parallel()

	const source = "alice@example.com"
	policy := &tailscale.ACL{}

	// Every autogroup this package names, plus forms it deliberately does not
	// resolve, plus a stand-in for one Tailscale adds after this release.
	candidates := []string{
		"autogroup:self", "autogroup:member", "autogroup:members",
		"autogroup:tagged", "autogroup:internet", "autogroup:danger-all",
		"autogroup:shared", "autogroup:admin", "autogroup:owner",
		"autogroup:billing-admin", "autogroup:it-admin",
		"autogroup:network-admin", "autogroup:auditor",
		"autogroup:invented-after-this-release",
	}
	// Spans every queryTarget: a user (equal to source, for self), a tag, a
	// tailnet device address, and a public address (for internet).
	queries := []string{source, "bob@example.com", "tag:web", "100.64.0.9", "8.8.8.8"}

	for _, selector := range candidates {
		t.Run(selector, func(t *testing.T) {
			t.Parallel()
			matchable := false
			for _, query := range queries {
				if policycore.SelectorMatches(selector, query, policy, source) {
					matchable = true
					break
				}
			}
			if known := policycore.KnownAutogroup(selector); known != matchable {
				t.Errorf(
					"KnownAutogroup(%q) = %v but resolver matchable = %v; "+
						"the recognized set and the resolver have drifted",
					selector, known, matchable,
				)
			}
		})
	}
}

func TestDangerAllMatchesEveryDevice(t *testing.T) {
	t.Parallel()
	policy := &tailscale.ACL{}
	for _, query := range []string{"100.64.0.9", "tag:web", "alice@example.com", "8.8.8.8"} {
		if !policycore.SelectorMatches("autogroup:danger-all", query, policy, "alice@example.com") {
			t.Errorf("SelectorMatches(danger-all, %q) = false, want true", query)
		}
	}
}

// allAutogroupSelectors lists every autogroup this package could be asked
// about, including the ones it deliberately does not resolve. Like
// roleAutogroupSelectors it is a test-local literal on purpose: an independent
// restatement of the set is what makes the drift guards meaningful. It must
// never be refactored to read from the package's own descriptor, or the guards
// become tautologies.
func allAutogroupSelectors() []string {
	return append(roleAutogroupSelectors(),
		"autogroup:self",
		"autogroup:member",
		"autogroup:members",
		"autogroup:tagged",
		"autogroup:internet",
		"autogroup:danger-all",
		"autogroup:shared",
		"autogroup:nonroot",
	)
}

// TestKnownAutogroupAndRoleAutogroupAreExclusive proves no autogroup is both
// confirmable offline and resolved from the user roster.
//
// KnownAutogroup vouches for selectors this package can confirm from the policy
// document alone; a role autogroup can only ever be refuted offline (a tagged
// device has no user owner) and needs the roster to be confirmed. A selector
// claimed by both would mean one of the two answers is wrong, and callers would
// get a confident verdict from a question that was never settled.
func TestKnownAutogroupAndRoleAutogroupAreExclusive(t *testing.T) {
	t.Parallel()

	for _, selector := range allAutogroupSelectors() {
		t.Run(selector, func(t *testing.T) {
			t.Parallel()

			if policycore.KnownAutogroup(selector) && policycore.IsRoleAutogroup(selector) {
				t.Errorf(
					"%q is both KnownAutogroup and IsRoleAutogroup; "+
						"a role autogroup is never confirmable without the roster",
					selector,
				)
			}
		})
	}
}

// TestRoleAutogroupsAgreeAcrossEveryView is the drift guard for the role set.
//
// The six role autogroups are consumed by four different views, and before the
// descriptor refactor the set was enumerated in two places that could disagree.
// Driving an independent list through IsRoleAutogroup, KnownAutogroup, and
// AutogroupResolvable (Matcher.directMatches is covered separately by
// selector_test.go) catches a role this list still expects that the switch no
// longer provides: one missing from the resolver understates coverage, one
// missing from the decidability rule turns a settleable tag query into a
// spurious Unresolvable and a spurious exit 10. It does not catch the
// reverse — a role added to the switch but never added to this list — which
// is the correct blind spot, since this list exists to check the descriptor,
// not the other way around.
func TestRoleAutogroupsAgreeAcrossEveryView(t *testing.T) {
	t.Parallel()

	withRoster := policycore.Matcher{
		Policy:    &policycore.Policy{ACL: &tailscale.ACL{}},
		Roles:     map[string]tailscale.UserRole{"ada@example.com": tailscale.UserRoleAdmin},
		HaveRoles: true,
	}
	for _, selector := range roleAutogroupSelectors() {
		t.Run(selector, func(t *testing.T) {
			t.Parallel()

			if !policycore.IsRoleAutogroup(selector) {
				t.Errorf("IsRoleAutogroup(%q) = false; want true", selector)
			}
			if policycore.KnownAutogroup(selector) {
				t.Errorf("KnownAutogroup(%q) = true; want false, the roster is required", selector)
			}
			if !policycore.AutogroupResolvable(selector, "tag:web") {
				t.Errorf(
					"AutogroupResolvable(%q, \"tag:web\") = false; "+
						"a tagged device has no user owner, so a tag refutes it with certainty",
					selector,
				)
			}
			if policycore.AutogroupResolvable(selector, "ada@example.com") {
				t.Errorf(
					"AutogroupResolvable(%q, \"ada@example.com\") = true; "+
						"deciding which role a login holds needs the roster",
					selector,
				)
			}
			if got := withRoster.MatchesTri(
				selector, "ada@example.com", "",
			); got == policycore.Unresolvable {
				t.Errorf(
					"MatchesTri(%q, \"ada@example.com\") = Unresolvable with a roster; "+
						"a complete roster settles every role against a login",
					selector,
				)
			}
			if got := withRoster.MatchesTri(
				selector, "100.64.0.9", "",
			); got != policycore.Unresolvable {
				t.Errorf(
					"MatchesTri(%q, \"100.64.0.9\") = %v with a roster; want Unresolvable "+
						"because a login-to-role roster cannot identify a device's owner",
					selector,
					got,
				)
			}
		})
	}
}

func TestSelectorMatchesTriIsTheZeroRosterMatcher(t *testing.T) {
	t.Parallel()

	const source = "alice@example.com"
	policy := &tailscale.ACL{
		Groups: map[string][]string{
			"group:eng": {"alice@example.com", "autogroup:shared"},
		},
		Hosts: map[string]string{"web": "10.1.0.0/16"},
	}
	matcher := policycore.Matcher{Policy: &policycore.Policy{ACL: policy}}

	singles := []struct {
		selector string
		query    string
	}{
		{"*", "100.64.0.9"},
		{"tag:web", "tag:web"},
		{"group:eng", "alice@example.com"},
		{"web", "10.1.2.3"},
		{"autogroup:self", source},
		{"autogroup:admin", "ada@example.com"},
		{"autogroup:admin", "tag:web"},
		{"autogroup:tagged", "100.64.0.9"},
		{"autogroup:shared", "tag:web"},
		{"group://partner/eng", "alice@example.com"},
		{"tag://partner/batch", "tag:web"},
		{"group://partner", "alice@example.com"},
	}
	for _, test := range singles {
		got := policycore.SelectorMatchesTri(test.selector, test.query, policy, source)
		want := matcher.MatchesTri(test.selector, test.query, source)
		if got != want {
			t.Errorf(
				"SelectorMatchesTri(%q, %q) = %v; zero-roster Matcher.MatchesTri = %v",
				test.selector,
				test.query,
				got,
				want,
			)
		}
	}

	lists := []struct {
		selectors []string
		query     string
	}{
		{nil, "tag:web"},
		{[]string{"tag:db", "tag:web"}, "tag:web"},
		{[]string{"autogroup:admin", "alice@example.com"}, "alice@example.com"},
		{[]string{"autogroup:admin", "autogroup:shared"}, "ada@example.com"},
		{[]string{"tag:db", "alice@example.com"}, "tag:web"},
		{[]string{"tag:db", "group://partner/eng"}, "ada@example.com"},
		{[]string{"group://partner/eng", "alice@example.com"}, "alice@example.com"},
	}
	for _, test := range lists {
		gotMatch, gotUnresolved := policycore.AnySelectorMatchesTri(
			test.selectors, test.query, policy, source,
		)
		wantMatch, wantUnresolved := matcher.AnyMatchesTri(test.selectors, test.query, source)
		if gotMatch != wantMatch || gotUnresolved != wantUnresolved {
			t.Errorf(
				"AnySelectorMatchesTri(%q, %q) = (%v, %q); "+
					"zero-roster Matcher.AnyMatchesTri = (%v, %q)",
				test.selectors,
				test.query,
				gotMatch,
				gotUnresolved,
				wantMatch,
				wantUnresolved,
			)
		}
	}
}
