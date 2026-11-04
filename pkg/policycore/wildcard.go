package policycore

import "strings"

// ContainsLiteralWildcard reports whether selectors contains the literal "*"
// selector. Callers whose policy surface attaches ports to destinations must
// strip those ports first, so "*:443" and "*:*" become the same literal host
// selector the tsacl overbroad-wildcard advisory owns.
//
// This intentionally does not treat autogroups as wildcards. In particular,
// autogroup:tagged can name most of a live fleet, but only control-plane state
// can answer whether it does; tailnet-audit owns that dynamic question.
func ContainsLiteralWildcard(selectors []string) bool {
	for _, selector := range selectors {
		if strings.TrimSpace(selector) == "*" {
			return true
		}
	}
	return false
}
