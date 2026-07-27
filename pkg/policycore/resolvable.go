package policycore

import (
	"strings"

	tailscale "tailscale.com/client/tailscale/v2"
)

// Match is the outcome of resolving a selector against a query.
//
// A policy file does not contain every fact a membership decision depends on.
// The role autogroups resolve against control-plane state an offline evaluator
// never sees, so collapsing "cannot tell" into "does not match" yields a
// confident wrong answer — the one outcome a reachability or coverage verdict
// must never produce. Match keeps that third state addressable instead.
type Match int

const (
	// NoMatch means the selector provably does not name the query.
	NoMatch Match = iota
	// Matched means the selector names the query.
	Matched
	// Unresolvable means membership depends on control-plane state this
	// package cannot see, so neither Matched nor NoMatch can be claimed.
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

// AutogroupResolvable reports whether this selector's membership can be decided
// against this query without control-plane state. Decidability is a property of
// the pair, not of the selector alone: autogroup:tagged is settled against
// "tag:batch" and against a user identity, but against "100.64.0.9" it needs
// the device-to-tag map, which lives in the control plane. Answering such a
// query "no match" would be exactly the confident wrong answer Match exists to
// prevent — and reporting a settleable one Unresolvable trains callers to
// ignore the state, so both directions matter.
func AutogroupResolvable(selector, query string) bool {
	if !strings.HasPrefix(selector, autogroupPrefix) {
		return true
	}
	spec, ok := autogroupSpecFor(selector)
	if !ok {
		return false
	}
	return spec.settles(classifyQuery(query))
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
	if SelectorMatches(selector, query, policy, source) {
		return Matched
	}
	if !AutogroupResolvable(selector, query) {
		return Unresolvable
	}
	return NoMatch
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
	unresolved := ""
	for _, selector := range selectors {
		if SelectorMatches(selector, query, policy, source) {
			return Matched, ""
		}
		if unresolved == "" && !AutogroupResolvable(selector, query) {
			unresolved = selector
		}
	}
	if unresolved != "" {
		return Unresolvable, unresolved
	}
	return NoMatch, ""
}
