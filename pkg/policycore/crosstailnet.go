package policycore

import (
	"github.com/rshade/tail-acl/pkg/policycore/alpha"
)

// crossTailnetSpec is everything this package knows about one cross-tailnet
// selector: the parsed selector when the grammar accepted it, or the parse
// error when it did not. Exactly one of the two is set.
//
// It is the counterpart of autogroupSpec and exists for the same reason. The
// cross-tailnet vocabulary is enumerated once, and IsCrossTailnetSelector,
// Matcher.Recognized, and the resolvability walk are all views of
// crossTailnetSpecFor, so a cross-tailnet selector cannot be half-recognized:
// either every view agrees it is one, or every view treats it as an ordinary
// local selector.
type crossTailnetSpec struct {
	selector alpha.ExternalSelector
	parseErr error
}

// crossTailnetSpecFor reports whether selector belongs to the cross-tailnet
// vocabulary, and describes it when it does. Membership is decided by
// alpha.LooksLikeExternalSelector rather than by a prefix list of this
// package's own, so the matcher and the parser cannot disagree about where the
// grammar's boundary lies.
func crossTailnetSpecFor(selector string) (crossTailnetSpec, bool) {
	if !alpha.LooksLikeExternalSelector(selector) {
		return crossTailnetSpec{}, false
	}
	parsed, err := alpha.ParseExternalSelector(selector)
	if err != nil {
		return crossTailnetSpec{parseErr: err}, true
	}
	return crossTailnetSpec{selector: parsed}, true
}

// crossTailnetSettles reports whether this matcher can decide spec. Unlike an
// autogroup, the query contributes nothing: an external tailnet's identities
// are opaque to this policy, so no local query shape carries the certainty a
// tag carries against a role autogroup, and nothing here can refute a declared
// external reference.
//
// Exactly one case settles. A well-formed selector whose alias is absent from
// declarations this matcher actually read is named by nothing in this policy —
// the reading the resolvability walk already gives an undefined group. A
// malformed selector settles nothing, because the :// prefix declares intent
// and makes it a mistyped cross-tailnet reference rather than a string that
// happens to name nobody. Neither does any selector when the declarations were
// not read, because an absent alias is then indistinguishable from a field the
// caller never parsed.
func (m Matcher) crossTailnetSettles(spec crossTailnetSpec) bool {
	if spec.parseErr != nil {
		return false
	}
	if _, haveDeclarations := m.externalTailnets(); !haveDeclarations {
		return false
	}
	return !m.KnownExternalTailnetAlias(spec.selector.Alias)
}

// IsCrossTailnetSelector reports whether selector uses the cross-tailnet
// group://<alias>/<name> or tag://<alias>/<name> grammar, which names members
// of another tailnet rather than of this one.
//
// It reports true for a malformed cross-tailnet selector as well. A mistyped
// cross-tailnet reference is still a cross-tailnet reference, and treating it
// as an ordinary local selector would report an authoring typo as "this rule
// names nobody" instead of "this cannot be decided from this policy".
func IsCrossTailnetSelector(selector string) bool {
	_, ok := crossTailnetSpecFor(selector)
	return ok
}

// KnownExternalTailnetAlias reports whether this matcher's policy declares
// alias as an external tailnet. It is the single lookup every cross-tailnet
// view goes through, so no two of them can disagree about which aliases exist.
//
// A false result means "not declared by a policy whose declarations were
// read", which a matcher that never read them cannot distinguish from "not
// declared at all" — so such a matcher reports false for every alias. Use
// Recognized or MatchesTri when the difference matters; both keep an
// unreadable declaration undecidable rather than reporting it absent.
func (m Matcher) KnownExternalTailnetAlias(alias string) bool {
	declarations, haveDeclarations := m.externalTailnets()
	if !haveDeclarations {
		return false
	}
	_, declared := declarations[alias]
	return declared
}
