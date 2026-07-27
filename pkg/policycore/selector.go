package policycore

import (
	"strings"

	tailscale "tailscale.com/client/tailscale/v2"
)

// Matcher resolves policy selectors against a query identity. Policy is the
// tailnet policy document; Roles and HaveRoles carry the live tailnet fact that
// document cannot supply — who holds which role, and whether that roster was
// read at all.
//
// When HaveRoles is false, role autogroups resolve to nothing and Recognized
// reports them as unresolved rather than unmatched, so a caller degrades to
// "coverage may be understated" instead of claiming a device is ungoverned.
// HaveRoles true with an empty Roles map is different: the roster was read and
// no user holds any role, so role autogroups are recognized and match nobody. A
// static policy tool that has no tailnet access leaves HaveRoles false.
type Matcher struct {
	Policy *tailscale.ACL
	// Roles maps a user's login name, lowercased, to their tailnet role.
	Roles map[string]tailscale.UserRole
	// HaveRoles reports that Roles came from a successfully read user roster.
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

func (m Matcher) groupMatches(selector, query, source string, seenGroups map[string]bool) bool {
	members, ok := m.Policy.Groups[selector]
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
