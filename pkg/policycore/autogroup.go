package policycore

import (
	"strings"

	tailscale "tailscale.com/client/tailscale/v2"
)

// autogroupSpec is everything this package knows about one autogroup: the role
// it selects, which query shapes settle it without control-plane state, and how
// it is matched from the policy document alone.
//
// It exists so the autogroup vocabulary is enumerated once. IsRoleAutogroup,
// KnownAutogroup, AutogroupResolvable, and Matcher.directMatches are all views
// of autogroupSpecFor, so an autogroup cannot be half-added: a selector either
// has a spec and every view agrees about it, or it has none and every view
// treats it as unknown.
type autogroupSpec struct {
	// role is the tailnet role this autogroup selects, empty for autogroups
	// that name something other than a role.
	role tailscale.UserRole
	// settles reports whether a query of this shape decides membership without
	// control-plane state.
	settles func(queryTarget) bool
	// matches reports whether the autogroup names query using only the policy
	// document. Nil when no offline fact can confirm it: the role autogroups,
	// which resolve through Matcher's user roster instead.
	matches func(m Matcher, query, source string) bool
}

// autogroupSpecFor is the single enumeration point for every autogroup this
// package understands. A selector absent from it is unknown: matched by
// nothing and refutable against nothing, which is the correct reading both of
// autogroup:shared — shared membership is about devices reaching in from
// another tailnet, so a tag refutes nothing about it — and of any autogroup
// Tailscale adds after this release.
func autogroupSpecFor(selector string) (autogroupSpec, bool) {
	switch selector {
	case autogroupDangerAll:
		// Matches every device including ones outside the tailnet (it restores
		// the pre-mitigation meaning of "*"), so there is nothing to look up
		// and no query shape that could refute it.
		return autogroupSpec{settles: settlesAlways, matches: matchesAlways}, true
	case autogroupInternet:
		// Decided by address arithmetic on the query alone.
		return autogroupSpec{settles: settlesAlways, matches: matchesInternet}, true
	case autogroupSelf:
		return autogroupSpec{settles: settlesAgainstUser, matches: matchesSelf}, true
	case autogroupMember, autogroupMembers:
		return autogroupSpec{settles: settlesUnlessBareDevice, matches: matchesMember}, true
	case autogroupTagged:
		return autogroupSpec{settles: settlesUnlessBareDevice, matches: matchesTagged}, true
	case autogroupOwner:
		return roleSpec(tailscale.UserRoleOwner), true
	case autogroupAdmin:
		return roleSpec(tailscale.UserRoleAdmin), true
	case autogroupITAdmin:
		return roleSpec(tailscale.UserRoleITAdmin), true
	case autogroupNetworkAdmin:
		return roleSpec(tailscale.UserRoleNetworkAdmin), true
	case autogroupBillingAdmin:
		return roleSpec(tailscale.UserRoleBillingAdmin), true
	case autogroupAuditor:
		return roleSpec(tailscale.UserRoleAuditor), true
	default:
		return autogroupSpec{}, false
	}
}

// roleSpec describes a role autogroup. matches stays nil: a tagged device has
// no user owner, so a tag refutes a role autogroup with certainty, but nothing
// in the policy document ever confirms one — that needs the user roster, which
// Matcher supplies.
//
// The mapping is flat, not hierarchical. Tailscale documents autogroup:admin as
// "all members in the tailnet with the Admin role", and gives every other role
// its own autogroup, so an Owner is not an Admin here and must not be treated
// as one.
func roleSpec(role tailscale.UserRole) autogroupSpec {
	return autogroupSpec{role: role, settles: settlesAgainstTag}
}

func settlesAlways(queryTarget) bool { return true }

func settlesAgainstUser(target queryTarget) bool { return target == queryUser }

func settlesAgainstTag(target queryTarget) bool { return target == queryTag }

// settlesUnlessBareDevice covers the autogroups a user or a tag settles by
// definition: a user is a member and is never tagged, and a tag is the
// converse. A bare device address is neither until the control plane says whose
// it is.
func settlesUnlessBareDevice(target queryTarget) bool { return target != queryDevice }

func matchesAlways(Matcher, string, string) bool { return true }

func matchesInternet(m Matcher, query, _ string) bool { return IsPublicAddress(query, m.Policy) }

func matchesSelf(_ Matcher, query, source string) bool {
	return query == source && LooksLikeUser(query)
}

func matchesMember(_ Matcher, query, _ string) bool { return LooksLikeUser(query) }

func matchesTagged(_ Matcher, query, _ string) bool { return strings.HasPrefix(query, tagPrefix) }
