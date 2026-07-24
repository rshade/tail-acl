package policycore

import (
	"strings"

	tailscale "tailscale.com/client/tailscale/v2"
)

// AnySelectorMatches reports whether any selector names query. source is the
// requesting identity, used only to resolve autogroup:self.
func AnySelectorMatches(selectors []string, query string, policy *tailscale.ACL, source string) bool {
	for _, selector := range selectors {
		if SelectorMatches(selector, query, policy, source) {
			return true
		}
	}
	return false
}

// SelectorMatches reports whether one selector names query.
func SelectorMatches(selector, query string, policy *tailscale.ACL, source string) bool {
	return selectorMatchesSeen(selector, query, policy, source, make(map[string]bool))
}

func selectorMatchesSeen(
	selector, query string,
	policy *tailscale.ACL,
	source string,
	seenGroups map[string]bool,
) bool {
	if directSelectorMatches(selector, query, policy, source) {
		return true
	}
	if groupSelectorMatches(selector, query, policy, source, seenGroups) {
		return true
	}
	return addressSelectorsMatch(selector, query, policy)
}

func directSelectorMatches(selector, query string, policy *tailscale.ACL, source string) bool {
	return selector == "*" || selector == query ||
		(selector == "autogroup:self" && query == source && LooksLikeUser(query)) ||
		((selector == "autogroup:member" || selector == "autogroup:members") && LooksLikeUser(query)) ||
		(selector == "autogroup:internet" && IsPublicAddress(query, policy)) ||
		(selector == "autogroup:tagged" && strings.HasPrefix(query, "tag:"))
}

func groupSelectorMatches(
	selector, query string,
	policy *tailscale.ACL,
	source string,
	seenGroups map[string]bool,
) bool {
	members, ok := policy.Groups[selector]
	if !ok || seenGroups[selector] {
		return false
	}
	seenGroups[selector] = true
	defer delete(seenGroups, selector)
	for _, member := range members {
		if selectorMatchesSeen(member, query, policy, source, seenGroups) {
			return true
		}
	}
	return false
}

func addressSelectorsMatch(selector, query string, policy *tailscale.ACL) bool {
	selectorValues := ExpandAddressSelector(selector, policy)
	queryValues := ExpandAddressSelector(query, policy)
	for _, selectorValue := range selectorValues {
		for _, queryValue := range queryValues {
			if selectorValue == "autogroup:internet" && IsPublicAddress(queryValue, policy) {
				return true
			}
			if AddressContains(selectorValue, queryValue) {
				return true
			}
		}
	}
	return false
}

// LooksLikeUser reports whether a selector names a user rather than a group.
func LooksLikeUser(selector string) bool {
	return strings.Contains(selector, "@") && !strings.HasPrefix(selector, "group:")
}
