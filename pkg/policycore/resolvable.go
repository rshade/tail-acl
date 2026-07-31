package policycore

import (
	"strings"

	tailscale "tailscale.com/client/tailscale/v2"
)

// Match is the outcome of resolving a selector against a query.
//
// A policy file does not contain every fact a membership decision depends on.
// Role autogroups resolve against control-plane state that only a matcher with a
// complete roster holds, so collapsing "cannot tell" into "does not match"
// yields a confident wrong answer — the one outcome a reachability or coverage
// verdict must never produce. Match keeps that third state addressable instead.
type Match int

const (
	// NoMatch means the selector provably does not name the query.
	NoMatch Match = iota
	// Matched means the selector names the query.
	Matched
	// Unresolvable means membership depends on control-plane state the matcher
	// does not have, so neither Matched nor NoMatch can be claimed.
	Unresolvable
)

const (
	tagPrefix       = "tag:"
	autogroupPrefix = "autogroup:"

	autogroupSelf      = "autogroup:self"
	autogroupMember    = "autogroup:member"
	autogroupMembers   = "autogroup:members"
	autogroupInternet  = "autogroup:internet"
	autogroupTagged    = "autogroup:tagged"
	autogroupDangerAll = "autogroup:danger-all"

	autogroupAdmin        = "autogroup:admin"
	autogroupOwner        = "autogroup:owner"
	autogroupBillingAdmin = "autogroup:billing-admin"
	autogroupITAdmin      = "autogroup:it-admin"
	autogroupNetworkAdmin = "autogroup:network-admin"
	autogroupAuditor      = "autogroup:auditor"
)

// queryTarget is what a query names, which decides which autogroups can be
// settled against it without the control plane.
type queryTarget int

const (
	// queryDevice is an IP, CIDR, or host alias. Whose device it is, and
	// whether it carries a tag, is control-plane state.
	queryDevice queryTarget = iota
	// queryUser is a user identity.
	queryUser
	// queryTag is a tagged device, which by definition has no user owner.
	queryTag
)

// queryContext is everything outside the selector that decides whether a query
// settles it: the shape of the query, plus the live facts the matcher holds.
// Roster availability is the only live fact today; a device-to-owner map would
// be the next, and belongs here rather than in a caller-side special case.
type queryContext struct {
	target    queryTarget
	haveRoles bool
}

func classifyQuery(query string) queryTarget {
	switch {
	case LooksLikeUser(query):
		return queryUser
	case strings.HasPrefix(query, tagPrefix):
		return queryTag
	default:
		return queryDevice
	}
}

// autogroupResolvable reports whether this matcher holds enough information to
// decide selector against query. It deliberately reads only HaveRoles and the
// autogroup descriptor, never Policy, so the zero-value Matcher used by
// AutogroupResolvable is safe.
func (m Matcher) autogroupResolvable(selector, query string) bool {
	if !strings.HasPrefix(selector, autogroupPrefix) {
		return true
	}
	spec, ok := autogroupSpecFor(selector)
	if !ok {
		return false
	}
	return spec.settles(queryContext{
		target:    classifyQuery(query),
		haveRoles: m.HaveRoles,
	})
}

// AutogroupResolvable is the roster-blind view of whether this selector's
// membership can be decided against this query without control-plane state.
// Decidability is a property of the pair, not of the selector alone:
// autogroup:tagged is settled against "tag:batch" and against a user identity,
// but against "100.64.0.9" it needs the device-to-tag map, which lives in the
// control plane. Answering such a query "no match" would be exactly the
// confident wrong answer Match exists to prevent — and reporting a settleable
// one Unresolvable trains callers to ignore the state, so both directions
// matter.
func AutogroupResolvable(selector, query string) bool {
	return Matcher{}.autogroupResolvable(selector, query)
}

// KnownAutogroup reports whether selector is an autogroup whose membership this
// package can ever confirm, independent of any particular query. Callers that
// grade a whole policy rather than one query use it to flag autogroups whose
// presence makes a verdict provisional, so the list lives here rather than
// being restated per tool.
//
// The role autogroups are deliberately excluded: a tag refutes them, but no
// offline fact confirms them. Use AutogroupResolvable when a query is in hand —
// a known autogroup can still be undecidable against a given query.
func KnownAutogroup(selector string) bool {
	spec, ok := autogroupSpecFor(selector)
	return ok && spec.matches != nil
}

// SelectorMatchesTri resolves one selector against query, reporting
// Unresolvable rather than NoMatch when the answer depends on control-plane
// state. source is the requesting identity, used only to resolve
// autogroup:self.
func SelectorMatchesTri(selector, query string, policy *tailscale.ACL, source string) Match {
	return Matcher{Policy: policy}.MatchesTri(selector, query, source)
}

// AnySelectorMatchesTri resolves a selector list against query. A match by any
// selector settles the list, so it outranks an earlier undecidable one. When
// nothing matches it returns Unresolvable along with the first selector that
// could not be decided, which callers surface as the reason.
func AnySelectorMatchesTri(
	selectors []string,
	query string,
	policy *tailscale.ACL,
	source string,
) (Match, string) {
	return Matcher{Policy: policy}.AnyMatchesTri(selectors, query, source)
}
