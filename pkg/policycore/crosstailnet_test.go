package policycore_test

import (
	"testing"

	tailscale "tailscale.com/client/tailscale/v2"

	"github.com/rshade/tail-acl/pkg/policycore"
)

// TestIsCrossTailnetSelectorAgreesWithTheParser is the guard against the drift
// this design exists to prevent: a second prefix list in policycore that fell
// out of step with the parser's would route a real cross-tailnet selector down the
// local path, where it reads as a definite non-match.
//
// It also pins IsCrossTailnetSelector's own values, rather than a second table
// restating them: TestLooksLikeExternalSelector fixes what the parser
// recognizes, and this fixes the two as equal.
func TestIsCrossTailnetSelectorAgreesWithTheParser(t *testing.T) {
	t.Parallel()

	corpus := []string{
		"group://partner/eng", "tag://partner/batch", "group://partner", "tag://",
		"group:///eng", "group://partner/eng/oncall", "group:eng", "tag:batch",
		"user://partner/alice", " group://partner/eng", "autogroup:admin",
		"ada@example.com", "100.64.0.9", "*", "",
	}

	for _, selector := range corpus {
		t.Run(selector, func(t *testing.T) {
			t.Parallel()

			if got, want := policycore.IsCrossTailnetSelector(selector),
				policycore.LooksLikeExternalSelector(selector); got != want {
				t.Errorf("IsCrossTailnetSelector(%q) = %t, but policycore.LooksLikeExternalSelector = %t",
					selector, got, want)
			}
		})
	}
}

func TestKnownExternalTailnetAlias(t *testing.T) {
	t.Parallel()

	declarations := map[string]tailscale.ExternalTailnet{
		"partner": {ExternalID: "tailnet-456", AllowIncomingConnections: true},
	}
	read := policycore.Matcher{Policy: &policycore.Policy{
		ACL:                  &tailscale.ACL{ExternalTailnets: declarations},
		HaveExternalTailnets: true,
	}}
	unread := policycore.Matcher{Policy: &policycore.Policy{
		ACL: &tailscale.ACL{ExternalTailnets: declarations},
	}}

	if !read.KnownExternalTailnetAlias("partner") {
		t.Error("KnownExternalTailnetAlias(partner) with declarations read = false, want true")
	}
	if read.KnownExternalTailnetAlias("typo") {
		t.Error("KnownExternalTailnetAlias(typo) with declarations read = true, want false")
	}
	if unread.KnownExternalTailnetAlias("partner") {
		t.Error("KnownExternalTailnetAlias(partner) with declarations unread = true, want false")
	}
	if (policycore.Matcher{}).KnownExternalTailnetAlias("partner") {
		t.Error("KnownExternalTailnetAlias(partner) on a zero Matcher = true, want false")
	}
}

// TestMatchesTriCrossTailnetDecisionTable is the spec's decision table read
// through the public resolver, which is where a caller actually meets it.
func TestMatchesTriCrossTailnetDecisionTable(t *testing.T) {
	t.Parallel()

	declarations := map[string]tailscale.ExternalTailnet{
		"partner": {ExternalID: "tailnet-456", AllowIncomingConnections: true},
	}
	read := policycore.Matcher{Policy: &policycore.Policy{
		ACL:                  &tailscale.ACL{ExternalTailnets: declarations},
		HaveExternalTailnets: true,
	}}
	unread := policycore.Matcher{Policy: &policycore.Policy{ACL: &tailscale.ACL{}}}

	tests := []struct {
		name     string
		matcher  policycore.Matcher
		selector string
		query    string
		want     policycore.Match
	}{
		{
			name: "declared group alias", matcher: read,
			selector: "group://partner/eng", query: "ada@example.com",
			want: policycore.Unresolvable,
		},
		{
			name: "declared tag alias against a tag query", matcher: read,
			selector: "tag://partner/batch", query: "tag:web",
			want: policycore.Unresolvable,
		},
		{
			name: "undeclared alias with declarations read", matcher: read,
			selector: "group://typo/eng", query: "ada@example.com",
			want: policycore.NoMatch,
		},
		{
			name: "undeclared alias with declarations unread", matcher: unread,
			selector: "group://typo/eng", query: "ada@example.com",
			want: policycore.Unresolvable,
		},
		{
			name: "malformed with declarations read", matcher: read,
			selector: "group://partner", query: "ada@example.com",
			want: policycore.Unresolvable,
		},
		{
			name: "malformed with declarations unread", matcher: unread,
			selector: "group://partner", query: "ada@example.com",
			want: policycore.Unresolvable,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			if got := test.matcher.MatchesTri(test.selector, test.query, ""); got != test.want {
				t.Errorf("MatchesTri(%q, %q) = %v, want %v", test.selector, test.query, got, test.want)
			}
		})
	}
}

// TestMatchesDoesNotMatchACrossTailnetSelector keeps the two-state callers
// conservative: the members a cross-tailnet selector names are described by
// another tailnet's policy, so nothing local may confirm them.
func TestMatchesDoesNotMatchACrossTailnetSelector(t *testing.T) {
	t.Parallel()

	matcher := policycore.Matcher{Policy: &policycore.Policy{
		ACL: &tailscale.ACL{
			ExternalTailnets: map[string]tailscale.ExternalTailnet{
				"partner": {ExternalID: "tailnet-456"},
			},
		},
		HaveExternalTailnets: true,
	}}

	for _, query := range []string{"ada@example.com", "tag:web", "100.64.0.9"} {
		if matcher.Matches("group://partner/eng", query, "") {
			t.Errorf("Matches(group://partner/eng, %q) = true, want false", query)
		}
	}
	if !matcher.Matches("*", "group://partner/eng", "") {
		t.Error("Matches(*, group://partner/eng) = false; the wildcard must keep its precedence")
	}
	if !matcher.Matches("group://partner/eng", "group://partner/eng", "") {
		t.Error("Matches on an identical selector and query = false; exact equality must keep its precedence")
	}
}

// TestAGroupsKeySpelledAsACrossTailnetSelectorStillMatchesLocally pins the
// union-of-readings rule at its most surprising point. A policy that defines a
// Groups key spelled as a cross-tailnet selector has defined a local group, and
// Matches reports its members — exactly as it does for a Groups key spelled
// "autogroup:admin". What must not happen is that local reading settling the
// cross-tailnet one, which TestMatchesTriCrossTailnetInsideGroups covers.
func TestAGroupsKeySpelledAsACrossTailnetSelectorStillMatchesLocally(t *testing.T) {
	t.Parallel()

	matcher := policycore.Matcher{Policy: &policycore.Policy{
		ACL: &tailscale.ACL{
			Groups: map[string][]string{
				"group://partner/eng": {"ada@example.com"},
			},
			ExternalTailnets: map[string]tailscale.ExternalTailnet{
				"partner": {ExternalID: "tailnet-456"},
			},
		},
		HaveExternalTailnets: true,
	}}

	if !matcher.Matches("group://partner/eng", "ada@example.com", "") {
		t.Error("Matches = false for a member of a locally defined group, want true")
	}
	if got := matcher.MatchesTri("group://partner/eng", "ada@example.com", ""); got != policycore.Matched {
		t.Errorf("MatchesTri = %v for a local member, want Matched", got)
	}
	if got := matcher.MatchesTri("group://partner/eng", "bob@example.com", ""); got != policycore.Unresolvable {
		t.Errorf("MatchesTri = %v for a non-member, want Unresolvable", got)
	}
}

func TestRecognizedCrossTailnetSelectors(t *testing.T) {
	t.Parallel()

	declarations := map[string]tailscale.ExternalTailnet{"partner": {ExternalID: "tailnet-456"}}
	read := policycore.Matcher{Policy: &policycore.Policy{
		ACL:                  &tailscale.ACL{ExternalTailnets: declarations},
		HaveExternalTailnets: true,
	}}
	unread := policycore.Matcher{Policy: &policycore.Policy{ACL: &tailscale.ACL{}}}

	tests := []struct {
		name     string
		matcher  policycore.Matcher
		selector string
		want     bool
	}{
		{name: "declared alias is not conclusive", matcher: read, selector: "group://partner/eng"},
		{name: "undeclared alias is conclusive", matcher: read, selector: "group://typo/eng", want: true},
		{name: "malformed is not conclusive", matcher: read, selector: "group://partner"},
		{name: "nothing is conclusive when unread", matcher: unread, selector: "group://typo/eng"},
		{name: "a local selector is still conclusive", matcher: read, selector: "group:eng", want: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			if got := test.matcher.Recognized(test.selector); got != test.want {
				t.Errorf("Recognized(%q) = %t, want %t", test.selector, got, test.want)
			}
		})
	}
}

// TestAutogroupResolvableReportsCrossTailnetSelectorsUndecidable pins the
// roster-blind view: holding no policy document, it holds no external-tailnet
// declarations either, so it cannot settle even an undeclared alias.
func TestAutogroupResolvableReportsCrossTailnetSelectorsUndecidable(t *testing.T) {
	t.Parallel()

	for _, selector := range []string{"group://partner/eng", "tag://partner/batch", "group://partner"} {
		if policycore.AutogroupResolvable(selector, "ada@example.com") {
			t.Errorf("AutogroupResolvable(%q) = true, want false", selector)
		}
	}
}

// TestMatchesTriCrossTailnetInsideGroups covers the two ways a cross-tailnet
// selector reaches the resolvers through the group walk rather than directly.
func TestMatchesTriCrossTailnetInsideGroups(t *testing.T) {
	t.Parallel()

	policy := &tailscale.ACL{
		Groups: map[string][]string{
			"group:mixed": {"ada@example.com", "group://partner/eng"},
			// A Groups key spelled as a cross-tailnet selector: the local
			// member list must not settle the cross-tailnet reading.
			"group://partner/eng": {"ada@example.com"},
		},
		ExternalTailnets: map[string]tailscale.ExternalTailnet{
			"partner": {ExternalID: "tailnet-456"},
		},
	}
	matcher := policycore.Matcher{Policy: &policycore.Policy{
		ACL:                  policy,
		HaveExternalTailnets: true,
	}}

	tests := []struct {
		name     string
		selector string
		query    string
		want     policycore.Match
	}{
		{
			name:     "a shadowing Groups key stays undecidable",
			selector: "group://partner/eng", query: "bob@example.com",
			want: policycore.Unresolvable,
		},
		{
			name:     "a group naming a cross-tailnet selector is undecidable for a non-member",
			selector: "group:mixed", query: "bob@example.com",
			want: policycore.Unresolvable,
		},
		{
			name:     "a definite member match outranks the undecidable sibling",
			selector: "group:mixed", query: "ada@example.com",
			want: policycore.Matched,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			if got := matcher.MatchesTri(test.selector, test.query, ""); got != test.want {
				t.Errorf("MatchesTri(%q, %q) = %v, want %v", test.selector, test.query, got, test.want)
			}
		})
	}
}

func TestAnyMatchesTriNamesACrossTailnetSelectorAsTheReason(t *testing.T) {
	t.Parallel()

	matcher := policycore.Matcher{Policy: &policycore.Policy{
		ACL: &tailscale.ACL{
			ExternalTailnets: map[string]tailscale.ExternalTailnet{
				"partner": {ExternalID: "tailnet-456"},
			},
		},
		HaveExternalTailnets: true,
	}}

	selectors := []string{"tag:db", "group://partner/eng", "group://typo/eng"}
	got, reason := matcher.AnyMatchesTri(selectors, "ada@example.com", "")
	if got != policycore.Unresolvable || reason != "group://partner/eng" {
		t.Errorf("AnyMatchesTri(%v) = (%v, %q), want (Unresolvable, \"group://partner/eng\")",
			selectors, got, reason)
	}

	withMatch := []string{"group://partner/eng", "ada@example.com"}
	got, reason = matcher.AnyMatchesTri(withMatch, "ada@example.com", "")
	if got != policycore.Matched || reason != "" {
		t.Errorf("AnyMatchesTri(%v) = (%v, %q), want (Matched, \"\")", withMatch, got, reason)
	}

	// Every selector decidable and none matching stays a definite NoMatch:
	// an undeclared alias must not leak undecidability into the list.
	onlyDecidable := []string{"tag:db", "group://typo/eng"}
	got, reason = matcher.AnyMatchesTri(onlyDecidable, "ada@example.com", "")
	if got != policycore.NoMatch || reason != "" {
		t.Errorf("AnyMatchesTri(%v) = (%v, %q), want (NoMatch, \"\")", onlyDecidable, got, reason)
	}
}

// TestPackageLevelEntryPointsReportCrossTailnetUnresolvable pins the documented
// equivalence: these forms take a bare ACL, so the container they build reports
// no declarations read and every cross-tailnet selector stays undecidable.
func TestPackageLevelEntryPointsReportCrossTailnetUnresolvable(t *testing.T) {
	t.Parallel()

	policy := &tailscale.ACL{}
	const selector = "group://partner/eng"

	if policycore.SelectorMatches(selector, "ada@example.com", policy, "") {
		t.Error("SelectorMatches on a cross-tailnet selector = true, want false")
	}
	if got := policycore.SelectorMatchesTri(selector, "ada@example.com", policy, ""); got != policycore.Unresolvable {
		t.Errorf("SelectorMatchesTri on a cross-tailnet selector = %v, want Unresolvable", got)
	}
	got, reason := policycore.AnySelectorMatchesTri([]string{selector}, "ada@example.com", policy, "")
	if got != policycore.Unresolvable || reason != selector {
		t.Errorf("AnySelectorMatchesTri = (%v, %q), want (Unresolvable, %q)", got, reason, selector)
	}
}

// TestPolicyContainerIsNilSafe pins the three ways a matcher can hold no
// document, which must stay indistinguishable to every resolver.
func TestPolicyContainerIsNilSafe(t *testing.T) {
	t.Parallel()

	matchers := map[string]policycore.Matcher{
		"zero matcher":       {},
		"nil container":      {Policy: nil},
		"container, nil ACL": {Policy: &policycore.Policy{}},
	}

	for name, matcher := range matchers {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			if matcher.Matches("group:eng", "ada@example.com", "") {
				t.Error("Matches(group:eng) = true, want false with no policy document")
			}
			if got := matcher.MatchesTri("group:eng", "ada@example.com", ""); got != policycore.NoMatch {
				t.Errorf("MatchesTri(group:eng) = %v, want NoMatch with no policy document", got)
			}
			if got := matcher.MatchesTri("group://partner/eng", "ada@example.com", ""); got != policycore.Unresolvable {
				t.Errorf("MatchesTri(group://partner/eng) = %v, want Unresolvable", got)
			}
		})
	}
}

// TestPolicyContainerPreservesACLMatching proves the embedded document still
// drives group, host, and ipset resolution exactly as a bare ACL did.
func TestPolicyContainerPreservesACLMatching(t *testing.T) {
	t.Parallel()

	matcher := policycore.Matcher{Policy: &policycore.Policy{ACL: &tailscale.ACL{
		Groups: map[string][]string{"group:eng": {"ada@example.com"}},
		Hosts:  map[string]string{"web": "10.1.0.0/16"},
	}}}

	if !matcher.Matches("group:eng", "ada@example.com", "") {
		t.Error("Matches(group:eng, ada@example.com) = false, want true through the container")
	}
	if !matcher.Matches("web", "10.1.2.3", "") {
		t.Error("Matches(web, 10.1.2.3) = false, want true through the container")
	}
}
