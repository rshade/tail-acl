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

func TestDangerAllMatchesEveryDevice(t *testing.T) {
	t.Parallel()
	policy := &tailscale.ACL{}
	for _, query := range []string{"100.64.0.9", "tag:web", "alice@example.com", "8.8.8.8"} {
		if !policycore.SelectorMatches("autogroup:danger-all", query, policy, "alice@example.com") {
			t.Errorf("SelectorMatches(danger-all, %q) = false, want true", query)
		}
	}
}
