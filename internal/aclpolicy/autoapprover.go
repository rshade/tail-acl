package aclpolicy

import (
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	tailscale "tailscale.com/client/tailscale/v2"

	"github.com/rshade/tsacl/pkg/policycore"
)

// autoApproversKey* are the JSON member names an autoApprovers edit targets.
//
// WritePatch resolves only the top-level key against the file's own spelling
// (see resolveTopLevelKey), so these nested names are matched exactly. A legacy
// policy that capitalizes "Routes" or "ExitNode" therefore loads — encoding/json
// matches fields case-insensitively — but cannot be edited: the patch fails with
// "value not found" and leaves the file untouched. Rename the nested member to
// its lowercase spelling first. The one shape that does not fail closed is a
// legacy member whose value is null ("Routes": null), which takes the
// create-the-block branch and writes a second lowercase member beside it;
// checkDuplicateMembers compares names exactly, so it does not catch that pair.
//
// services is deliberately absent: no command authors it (see the issue's
// scope note), and remove's emptiness judgment only ever preserves it.
const (
	autoApproversKey         = "autoApprovers"
	autoApproversRoutesKey   = "routes"
	autoApproversExitNodeKey = "exitNode"
)

// AutoApproverEdit describes the syntax-tree changes needed for an
// autoApprovers edit. Callers apply Operations with WritePatch after loading
// the typed policy.
type AutoApproverEdit struct {
	Operations []PatchOperation

	// Route is the routes key the edit targeted, as the file spells it — which
	// is not always the canonical prefix the caller asked for (see
	// resolveRouteKey). A caller that names the edited node afterwards, to
	// attach a comment or to phrase a result message, must use this rather than
	// its own argument, or it addresses a member the patch never touched. It is
	// empty for an exit-node edit, which has no key.
	Route string
}

// Changed reports whether the edit has any file operations to apply.
func (e AutoApproverEdit) Changed() bool { return len(e.Operations) != 0 }

// AutoApproverSegments returns the path segments of the member an
// auto-approver comment belongs to: the route's member under
// autoApprovers.routes, or the autoApprovers.exitNode member when route is
// empty. The comment anchors to the member rather than to one approver
// element so a note recorded while adding one approver still describes the
// entry after a later edit adds or removes the others.
func AutoApproverSegments(route string) []string {
	if route == "" {
		return []string{autoApproversKey, autoApproversExitNodeKey}
	}
	return []string{autoApproversKey, autoApproversRoutesKey, route}
}

// NormalizeAutoApproverRoute canonicalizes a route key for
// autoApprovers.routes: the value must parse as a CIDR prefix and is masked
// to its base address, so "10.0.0.1/8" and "10.0.0.0/8" name the same key
// rather than forking it into two entries.
func NormalizeAutoApproverRoute(route string) (string, error) {
	route = strings.TrimSpace(route)
	if route == "" {
		return "", errors.New("route must not be empty")
	}
	prefix, err := netip.ParsePrefix(route)
	if err != nil {
		return "", fmt.Errorf("route %q is not a CIDR prefix: %w", route, err)
	}
	return prefix.Masked().String(), nil
}

// resolveRouteKey returns the key routes actually uses for the canonical
// prefix route, which a hand-authored policy may spell unmasked.
//
// Matching on the parsed prefix rather than the string is what keeps
// "10.0.0.1/8" a single entry: string lookup misses it, so add would fork a
// second "10.0.0.0/8" key beside the one the operator can see, and remove would
// report "not present" for an approver that is plainly there — a confident
// wrong answer, the one outcome the edit must never give. Resolving here keeps
// the file's own spelling, the same bargain resolveTopLevelKey strikes for a
// legacy capitalized policy key.
//
// An absent prefix resolves to the canonical spelling, so a new key is written
// the documented way.
//
// Several keys naming one prefix is refused rather than resolved, and the
// exact-match short-circuit is deliberately absent so that the canonical
// spelling cannot quietly win the tie. Editing one of them would leave the
// others approving the same prefix while the command reported success — a
// revocation that exits 0 with the privilege intact is the worst answer this
// edit can give, worse than the string-lookup miss that motivated matching on
// the prefix at all. "merge --dir" produces exactly this state from two
// fragments spelling one IPv6 prefix in different case, and checkDuplicateMembers
// cannot see it because the member names do differ. Refusing is the same answer
// checkDuplicateMembers gives for a genuine duplicate, and for the same reason.
func resolveRouteKey(routes map[string][]string, route string) (string, error) {
	var matches []string
	for _, key := range slices.Sorted(maps.Keys(routes)) {
		if canonical, err := NormalizeAutoApproverRoute(key); err == nil && canonical == route {
			matches = append(matches, key)
		}
	}
	switch len(matches) {
	case 0:
		return route, nil
	case 1:
		return matches[0], nil
	default:
		return "", fmt.Errorf(
			"autoApprovers.routes spells prefix %s as %s; merge them into one key first",
			route, strings.Join(matches, ", "))
	}
}

// AddRouteApprovers adds every absent approver to the route's list, merging
// into the existing entry rather than replacing the key. Approvers the list
// already carries produce no operation, so a repeat is a no-op instead of a
// duplicate. Each block level is created whole when absent, so the patch
// spells a new member the canonical way rather than appending into nothing.
func AddRouteApprovers(policy *Policy, route string, approvers []string) (AutoApproverEdit, error) {
	route, approvers, err := validateAutoApproverEdit(route, approvers)
	if err != nil {
		return AutoApproverEdit{}, err
	}
	var existing []string
	autoApprovers := policy.AutoApprovers
	if autoApprovers != nil {
		if route, err = resolveRouteKey(autoApprovers.Routes, route); err != nil {
			return AutoApproverEdit{}, err
		}
		existing = autoApprovers.Routes[route]
	}
	missing := missingApprovers(existing, approvers)
	edit := AutoApproverEdit{Route: route}
	if len(missing) == 0 {
		return edit, nil
	}
	switch {
	case autoApprovers == nil:
		edit.Operations = append(edit.Operations, PatchAdd(
			tailscale.ACLAutoApprovers{Routes: map[string][]string{route: missing}}, autoApproversKey))
	case autoApprovers.Routes == nil:
		edit.Operations = append(edit.Operations, PatchAdd(
			map[string][]string{route: missing}, autoApproversKey, autoApproversRoutesKey))
	case existing == nil:
		edit.Operations = append(edit.Operations, PatchAdd(
			missing, autoApproversKey, autoApproversRoutesKey, route))
	default:
		for _, approver := range missing {
			edit.Operations = append(edit.Operations, PatchAdd(
				approver, autoApproversKey, autoApproversRoutesKey, route, "-"))
		}
	}
	return edit, nil
}

// AddExitNodeApprovers adds every absent approver to the exit-node list, by
// the same idempotency rule as AddRouteApprovers.
func AddExitNodeApprovers(policy *Policy, approvers []string) (AutoApproverEdit, error) {
	approvers, err := validateAutoApproverSelectors(approvers)
	if err != nil {
		return AutoApproverEdit{}, err
	}
	var existing []string
	autoApprovers := policy.AutoApprovers
	if autoApprovers != nil {
		existing = autoApprovers.ExitNode
	}
	missing := missingApprovers(existing, approvers)
	var edit AutoApproverEdit
	if len(missing) == 0 {
		return edit, nil
	}
	switch {
	case autoApprovers == nil:
		edit.Operations = append(edit.Operations, PatchAdd(
			tailscale.ACLAutoApprovers{ExitNode: missing}, autoApproversKey))
	case existing == nil:
		edit.Operations = append(edit.Operations, PatchAdd(
			missing, autoApproversKey, autoApproversExitNodeKey))
	default:
		for _, approver := range missing {
			edit.Operations = append(edit.Operations, PatchAdd(
				approver, autoApproversKey, autoApproversExitNodeKey, "-"))
		}
	}
	return edit, nil
}

// RemoveRouteApprovers removes every occurrence of each named approver from
// the route's list — duplicates go together, so the edit stays idempotent on
// hand-edited input. A list emptied by the removal takes its key with it:
// "10.0.0.0/8": [] reads as a configured-but-empty approval rather than an
// absent one, the same rule test remove applies to an emptied assertion key.
// An emptied routes or autoApprovers block is pruned too, unless a comment is
// attached to it: PatchPruneEmpty never deletes authored text, the rule every
// remove command applies to its container.
func RemoveRouteApprovers(policy *Policy, route string, approvers []string) (AutoApproverEdit, error) {
	route, approvers, err := validateAutoApproverEdit(route, approvers)
	if err != nil {
		return AutoApproverEdit{}, err
	}
	autoApprovers := policy.AutoApprovers
	if autoApprovers == nil {
		return AutoApproverEdit{Route: route}, nil
	}
	if route, err = resolveRouteKey(autoApprovers.Routes, route); err != nil {
		return AutoApproverEdit{}, err
	}
	existing := autoApprovers.Routes[route]
	indexes := approverIndexes(existing, approvers)
	edit := AutoApproverEdit{Route: route}
	if len(indexes) == 0 {
		return edit, nil
	}
	if len(indexes) == len(existing) {
		edit.Operations = append(edit.Operations,
			PatchRemove(autoApproversKey, autoApproversRoutesKey, route))
		edit.Operations = append(edit.Operations, pruneAutoApprovers(autoApproversRoutesKey)...)
		return edit, nil
	}
	// Element removals walk backward so earlier indexes stay valid, the same
	// rule RemoveAssertions applies to test entries.
	for _, index := range slices.Backward(indexes) {
		edit.Operations = append(edit.Operations, PatchRemove(
			autoApproversKey, autoApproversRoutesKey, route, strconv.Itoa(index)))
	}
	return edit, nil
}

// RemoveExitNodeApprovers removes every occurrence of each named approver
// from the exit-node list. An emptied list takes the exitNode member with it
// — member-level pruning, exactly as RemoveRouteApprovers treats an emptied
// route key — and the autoApprovers block follows if it is left empty and
// uncommented.
func RemoveExitNodeApprovers(policy *Policy, approvers []string) (AutoApproverEdit, error) {
	approvers, err := validateAutoApproverSelectors(approvers)
	if err != nil {
		return AutoApproverEdit{}, err
	}
	autoApprovers := policy.AutoApprovers
	if autoApprovers == nil {
		return AutoApproverEdit{}, nil
	}
	existing := autoApprovers.ExitNode
	indexes := approverIndexes(existing, approvers)
	var edit AutoApproverEdit
	if len(indexes) == 0 {
		return edit, nil
	}
	if len(indexes) == len(existing) {
		edit.Operations = append(edit.Operations,
			PatchRemove(autoApproversKey, autoApproversExitNodeKey))
		edit.Operations = append(edit.Operations, pruneAutoApprovers("")...)
		return edit, nil
	}
	for _, index := range slices.Backward(indexes) {
		edit.Operations = append(edit.Operations, PatchRemove(
			autoApproversKey, autoApproversExitNodeKey, strconv.Itoa(index)))
	}
	return edit, nil
}

// pruneAutoApprovers lists the comment-aware prunes that follow a removal:
// the emptied member's section (routes, when given) and then the autoApprovers
// block. Each is dropped only if it is empty and carries no comment.
func pruneAutoApprovers(section string) []PatchOperation {
	var operations []PatchOperation
	if section != "" {
		operations = append(operations, PatchPruneEmpty(autoApproversKey, section))
	}
	return append(operations, PatchPruneEmpty(autoApproversKey))
}

func validateAutoApproverEdit(route string, approvers []string) (string, []string, error) {
	route, err := NormalizeAutoApproverRoute(route)
	if err != nil {
		return "", nil, err
	}
	approvers, err = validateAutoApproverSelectors(approvers)
	if err != nil {
		return "", nil, err
	}
	return route, approvers, nil
}

// validateAutoApproverSelectors trims, rejects unsupported selector kinds, and
// dedupes the approver list while preserving argument order, so one invocation
// can never author an unsupported approver kind or add the same selector twice.
func validateAutoApproverSelectors(approvers []string) ([]string, error) {
	if len(approvers) == 0 {
		return nil, errors.New("at least one approver is required")
	}
	seen := make(map[string]struct{}, len(approvers))
	validated := make([]string, 0, len(approvers))
	for _, approver := range approvers {
		approver = strings.TrimSpace(approver)
		if approver == "" {
			return nil, errors.New("approver must not be empty")
		}
		if !isAutoApproverSelector(approver) {
			return nil, fmt.Errorf(
				"approver %q is not supported; use a login email, group:, autogroup:, or tag: selector",
				approver)
		}
		if _, duplicate := seen[approver]; duplicate {
			continue
		}
		seen[approver] = struct{}{}
		validated = append(validated, approver)
	}
	return validated, nil
}

// isAutoApproverSelector reports whether selector is one of the identity kinds
// Tailscale permits for route and exit-node auto-approvers. The user:*@domain
// form is a domain autogroup despite its user: prefix. Other colon-prefixed
// values are selector namespaces, not login names, even if they contain an @.
// Autogroup names are intentionally accepted by prefix so a newly introduced
// Tailscale autogroup does not require a tsacl release before it can be used.
func isAutoApproverSelector(selector string) bool {
	switch {
	case strings.HasPrefix(selector, "group:"):
		return len(selector) > len("group:")
	case strings.HasPrefix(selector, "autogroup:"):
		return len(selector) > len("autogroup:")
	case strings.HasPrefix(selector, "tag:"):
		return len(selector) > len("tag:")
	case strings.HasPrefix(selector, "user:*@"):
		return len(selector) > len("user:*@")
	case strings.Contains(selector, ":"):
		return false
	default:
		return policycore.LooksLikeUser(selector)
	}
}

// missingApprovers returns the wanted approvers absent from existing, in
// argument order. Comparison is byte-exact: selector spelling is significant,
// and wanted arrives already trimmed and deduped.
func missingApprovers(existing, wanted []string) []string {
	var missing []string
	for _, approver := range wanted {
		if !slices.Contains(existing, approver) {
			missing = append(missing, approver)
		}
	}
	return missing
}

// approverIndexes returns the index of every element of existing naming one
// of the wanted approvers.
func approverIndexes(existing, wanted []string) []int {
	var indexes []int
	for index, approver := range existing {
		if slices.Contains(wanted, approver) {
			indexes = append(indexes, index)
		}
	}
	return indexes
}
