package policycore

import (
	"strings"

	tailscale "tailscale.com/client/tailscale/v2"
)

// Matcher resolves policy selectors against a query identity. Policy is the
// tailnet policy document; Roles and HaveRoles carry the live tailnet fact that
// document cannot supply — who holds which role, and whether a complete,
// authoritative roster was read.
//
// When HaveRoles is false, role autogroups resolve to nothing and Recognized
// reports them as unresolved rather than unmatched, so a caller degrades to
// "coverage may be understated" instead of claiming a device is ungoverned.
// HaveRoles true with an empty Roles map is different: the complete roster was
// read and no user holds any role, so role autogroups are recognized and match
// nobody. Callers must leave HaveRoles false after a partial, truncated, or
// failed read. A static policy tool that has no tailnet access leaves it false.
type Matcher struct {
	Policy *tailscale.ACL
	// Roles maps a user's login name, lowercased, to their tailnet role.
	Roles map[string]tailscale.UserRole
	// HaveRoles reports that Roles is a complete and authoritative user roster.
	HaveRoles bool
}

// Matches reports whether selector names query. source is the requesting
// identity, used only to resolve autogroup:self.
func (m Matcher) Matches(selector, query, source string) bool {
	return m.matchesSeen(selector, query, source, make(map[string]bool))
}

// AnyMatches reports whether any selector names query. source is the requesting
// identity, used only to resolve autogroup:self.
func (m Matcher) AnyMatches(selectors []string, query, source string) bool {
	for _, selector := range selectors {
		if m.Matches(selector, query, source) {
			return true
		}
	}
	return false
}

// MatchesTri resolves one selector against query with everything this matcher
// holds, reporting Unresolvable rather than NoMatch when the answer depends on
// state the matcher does not have. source is the requesting identity, used only
// to resolve autogroup:self.
func (m Matcher) MatchesTri(selector, query, source string) Match {
	if m.Matches(selector, query, source) {
		return Matched
	}
	if !m.autogroupResolvable(selector, query) {
		return Unresolvable
	}
	return NoMatch
}

// AnyMatchesTri resolves a selector list against query. A match by any selector
// settles the list, so it outranks an earlier undecidable one. When nothing
// matches it returns Unresolvable along with the first selector that could not
// be decided, which callers surface as the reason.
func (m Matcher) AnyMatchesTri(selectors []string, query, source string) (Match, string) {
	unresolved := ""
	for _, selector := range selectors {
		match := m.MatchesTri(selector, query, source)
		if match == Matched {
			return Matched, ""
		}
		if match == Unresolvable && unresolved == "" {
			unresolved = selector
		}
	}
	if unresolved != "" {
		return Unresolvable, unresolved
	}
	return NoMatch, ""
}

// SelectorMatches reports whether one selector names query using only what the
// policy document supplies. It is the roster-blind entry point the three-state
// resolvers in this package are built on, and the form callers with no tailnet
// access use; role autogroups therefore never match here, which is exactly what
// AutogroupResolvable reports as undecidable. A caller holding a user roster
// builds a Matcher instead.
func SelectorMatches(selector, query string, policy *tailscale.ACL, source string) bool {
	return Matcher{Policy: policy}.Matches(selector, query, source)
}

// Recognized reports whether this matcher understands selector well enough that
// a non-match means query is genuinely not named, rather than merely
// unevaluable. Every non-autogroup selector is recognized — tags, users, groups,
// hosts, ipsets, and addresses all resolve from the policy document alone — as
// are the autogroup forms this package resolves.
//
// Role autogroups are recognized only when the user roster was read. Without
// that live tailnet fact no caller can decide them, so a non-match must be
// reported as unresolved rather than as absence of coverage.
//
// Every other autogroup defers to KnownAutogroup rather than being re-listed
// here. Recognized is the roster-aware view of the same question KnownAutogroup
// answers for callers with no roster, and two copies of that list would drift
// the moment either learns a new autogroup — the drift this package exists to
// prevent.
func (m Matcher) Recognized(selector string) bool {
	if !strings.HasPrefix(selector, autogroupPrefix) {
		return true
	}
	if IsRoleAutogroup(selector) {
		return m.HaveRoles
	}
	return KnownAutogroup(selector)
}

func (m Matcher) matchesSeen(selector, query, source string, seenGroups map[string]bool) bool {
	if m.directMatches(selector, query, source) {
		return true
	}
	if m.groupMatches(selector, query, source, seenGroups) {
		return true
	}
	return m.addressMatches(selector, query)
}

// directMatches resolves selector against query without consulting groups or
// address expansion, which matchesSeen tries next. "*" and an exact string
// equality are handled before the descriptor because neither is an autogroup.
func (m Matcher) directMatches(selector, query, source string) bool {
	if selector == "*" || selector == query {
		return true
	}
	spec, ok := autogroupSpecFor(selector)
	if !ok {
		return false
	}
	return m.matchSpec(spec, query, source)
}

// matchSpec applies spec against query. It is factored out of directMatches so
// the malformed-descriptor guard below is independently testable: the real
// autogroupSpecFor switch never produces a spec with neither field set, so
// directMatches alone cannot exercise that branch.
func (m Matcher) matchSpec(spec autogroupSpec, query, source string) bool {
	if spec.role != "" {
		return m.roleMatches(spec.role, query)
	}
	// A spec with neither a role nor a match function is malformed: the
	// descriptor's invariant is that exactly one of the two is set. Report no
	// match rather than panicking, so a half-added autogroup degrades to
	// "not named by this selector" instead of taking down every caller.
	if spec.matches == nil {
		return false
	}
	return spec.matches(m, query, source)
}

// roleMatches reports whether query's login holds role. The lookup is
// lowercased because Device.User and User.LoginName are not guaranteed to agree
// on case, and a case difference must not silently drop coverage. An empty
// role is rejected outright: tailscale.UserRole is a string type, so a
// zero-value role would otherwise equal the zero value Roles[query] returns
// for any login absent from the roster, turning "no role specified" into a
// false match.
func (m Matcher) roleMatches(role tailscale.UserRole, query string) bool {
	if role == "" || !m.HaveRoles || !LooksLikeUser(query) {
		return false
	}
	return m.Roles[strings.ToLower(query)] == role
}

// groupMembers reports the members selector names as a group. It is the single
// lookup both the matching walk and the resolvability walk go through, so the
// two cannot disagree about which selectors are groups — a disagreement would
// let a group the matcher expands be reported as settled, which is a confident
// wrong answer rather than merely a missed one. Membership is keyed on the
// literal selector, not on the group: prefix, because that is what Matches
// resolves against; a nil Policy simply names no groups.
func (m Matcher) groupMembers(selector string) ([]string, bool) {
	if m.Policy == nil {
		return nil, false
	}
	members, ok := m.Policy.Groups[selector]
	return members, ok
}

func (m Matcher) groupMatches(selector, query, source string, seenGroups map[string]bool) bool {
	members, ok := m.groupMembers(selector)
	if !ok || seenGroups[selector] {
		return false
	}
	seenGroups[selector] = true
	defer delete(seenGroups, selector)
	for _, member := range members {
		if m.matchesSeen(member, query, source, seenGroups) {
			return true
		}
	}
	return false
}

func (m Matcher) addressMatches(selector, query string) bool {
	selectorValues := ExpandAddressSelector(selector, m.Policy)
	queryValues := ExpandAddressSelector(query, m.Policy)
	for _, selectorValue := range selectorValues {
		for _, queryValue := range queryValues {
			if selectorValue == autogroupInternet && IsPublicAddress(queryValue, m.Policy) {
				return true
			}
			if AddressContains(selectorValue, queryValue) {
				return true
			}
		}
	}
	return false
}

// IsRoleAutogroup reports whether selector is one of the role-based autogroups
// resolved from a tailnet's user roster rather than from the policy document.
func IsRoleAutogroup(selector string) bool {
	spec, ok := autogroupSpecFor(selector)
	return ok && spec.role != ""
}

// LooksLikeUser reports whether a selector names a user rather than a group.
func LooksLikeUser(selector string) bool {
	return strings.Contains(selector, "@") && !strings.HasPrefix(selector, "group:")
}
