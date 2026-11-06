package aclpolicy

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	tailscale "tailscale.com/client/tailscale/v2"
)

const (
	nodeAttrsKey      = "nodeAttrs"
	nodeAttrAttrKey   = "attr"
	nodeAttrIPPoolKey = "ipPool"
)

// NodeAttrSpec is the typed input shared by nodeattr add and nodeattr remove.
// Attr and IPPool are mutually exclusive: one invocation edits one kind of
// value on every matching target entry.
type NodeAttrSpec struct {
	Target []string
	Attr   []string
	IPPool []string
}

// NodeAttrEdit describes a comment-preserving nodeAttrs edit. Callers apply
// Operations with WritePatch after loading the complete typed policy.
type NodeAttrEdit struct {
	// EntryIndex names the entry an add authored into, so the caller can route
	// a comment to it. It is meaningful only for AddNodeAttr and
	// RemoveNodeAttrAt. RemoveNodeAttr leaves it -1: that call edits every
	// entry matching the target set and may prune some of them, so no single
	// index describes the result. Unlike SSHRuleEdit.RuleIndex, which the SSH
	// runner reads back, nothing consumes it on the remove path.
	EntryIndex int
	Operations []PatchOperation
}

// Changed reports whether the edit has file operations to apply.
func (e NodeAttrEdit) Changed() bool { return len(e.Operations) != 0 }

// AddNodeAttr adds values to the entry whose target set matches the requested
// target set. A matching entry is extended in place; a new entry is appended.
// Target order is identity-insensitive, while the first authored order is
// retained in the file. The operation values are deliberately local maps,
// rather than tailscale.NodeAttrGrant values: this editor must never marshal
// and replace the whole nodeAttrs section through the pinned client type.
func AddNodeAttr(policy *Policy, spec NodeAttrSpec) (NodeAttrEdit, error) {
	spec, err := validateNodeAttrSpec(spec)
	if err != nil {
		return NodeAttrEdit{}, err
	}
	wantKey := nodeAttrTargetKey(spec.Target)
	field := nodeAttrEditField(spec)
	// Every matching entry has to be consulted before deciding a value is
	// absent, because RemoveNodeAttr strips the value from all of them. An add
	// that stopped at the first match would author a duplicate of a value a
	// later entry already carries, and the natural undo would then prune that
	// pre-existing entry — destroying policy, and its comments, that the add
	// never created.
	target := -1
	missing := slices.Clone(nodeAttrEditValues(spec))
	for index, existing := range policy.NodeAttrs {
		if nodeAttrTargetKey(existing.Target) != wantKey {
			continue
		}
		if target < 0 {
			target = index
		}
		missing = nodeAttrMissing(existing, field, missing)
	}
	if target >= 0 {
		edit := NodeAttrEdit{EntryIndex: target}
		if len(missing) == 0 {
			return edit, nil
		}
		// The first matching entry is the write site so comment routing lands
		// where the README says it does.
		if len(existingField(policy.NodeAttrs[target], field)) == 0 {
			edit.Operations = append(edit.Operations,
				PatchAdd(missing, nodeAttrsKey, strconv.Itoa(target), field))
		} else {
			for _, value := range missing {
				edit.Operations = append(edit.Operations,
					PatchAdd(value, nodeAttrsKey, strconv.Itoa(target), field, "-"))
			}
		}
		return edit, nil
	}

	entry := map[string]any{
		"target": slices.Clone(spec.Target),
	}
	if len(spec.Attr) != 0 {
		entry[nodeAttrAttrKey] = slices.Clone(spec.Attr)
	} else {
		entry[nodeAttrIPPoolKey] = slices.Clone(spec.IPPool)
	}
	edit := NodeAttrEdit{EntryIndex: len(policy.NodeAttrs)}
	if policy.NodeAttrs == nil {
		edit.Operations = []PatchOperation{PatchAdd([]map[string]any{entry}, nodeAttrsKey)}
	} else {
		edit.Operations = []PatchOperation{PatchAdd(entry, nodeAttrsKey, "-")}
	}
	return edit, nil
}

// RemoveNodeAttr removes every matching value from every entry with the
// requested target set. Entries left with no attr, ipPool, or app data are
// pruned instead of becoming a target-only nodeAttrs entry.
func RemoveNodeAttr(policy *Policy, spec NodeAttrSpec) (NodeAttrEdit, error) {
	spec, err := validateNodeAttrSpec(spec)
	if err != nil {
		return NodeAttrEdit{}, err
	}
	wantKey := nodeAttrTargetKey(spec.Target)
	edit := NodeAttrEdit{EntryIndex: -1}
	for index := range slices.Backward(policy.NodeAttrs) {
		existing := policy.NodeAttrs[index]
		if nodeAttrTargetKey(existing.Target) != wantKey {
			continue
		}
		field := nodeAttrEditField(spec)
		values := existingField(existing, field)
		indexes := nodeAttrValueIndexes(field, values, nodeAttrEditValues(spec))
		if len(indexes) == 0 {
			continue
		}
		if len(indexes) == len(values) && nodeAttrEntryEmptyAfter(existing, field) {
			edit.Operations = append(edit.Operations, PatchRemove(nodeAttrsKey, strconv.Itoa(index)))
			continue
		}
		if len(indexes) == len(values) {
			edit.Operations = append(edit.Operations,
				PatchRemove(nodeAttrsKey, strconv.Itoa(index), field))
			continue
		}
		for _, valueIndex := range slices.Backward(indexes) {
			edit.Operations = append(edit.Operations, PatchRemove(
				nodeAttrsKey, strconv.Itoa(index), field, strconv.Itoa(valueIndex)))
		}
	}
	if len(edit.Operations) != 0 {
		edit.Operations = append(edit.Operations, PatchPruneEmpty(nodeAttrsKey))
	}
	return edit, nil
}

// RemoveNodeAttrAt removes one nodeAttrs entry by its zero-based index.
func RemoveNodeAttrAt(policy *Policy, index int) (NodeAttrEdit, error) {
	if index < 0 || index >= len(policy.NodeAttrs) {
		return NodeAttrEdit{}, fmt.Errorf(
			"nodeAttrs index %d is out of range; policy has %d nodeAttrs entries", index, len(policy.NodeAttrs),
		)
	}
	return NodeAttrEdit{
		EntryIndex: index,
		Operations: []PatchOperation{PatchRemove(nodeAttrsKey, strconv.Itoa(index)), PatchPruneEmpty(nodeAttrsKey)},
	}, nil
}

func validateNodeAttrSpec(spec NodeAttrSpec) (NodeAttrSpec, error) {
	target, err := normalizeNodeAttrValues("target", spec.Target)
	if err != nil {
		return NodeAttrSpec{}, err
	}
	attr, err := normalizeOptionalNodeAttrValues(nodeAttrAttrKey, spec.Attr)
	if err != nil {
		return NodeAttrSpec{}, err
	}
	pool, err := normalizeNodeAttrPools(spec.IPPool)
	if err != nil {
		return NodeAttrSpec{}, err
	}
	if len(attr) == 0 && len(pool) == 0 {
		return NodeAttrSpec{}, errors.New("nodeattr add/remove requires at least one --attr or --ip-pool")
	}
	if len(attr) != 0 && len(pool) != 0 {
		return NodeAttrSpec{}, errors.New("nodeattr --attr and --ip-pool are mutually exclusive")
	}
	return NodeAttrSpec{Target: target, Attr: attr, IPPool: pool}, nil
}

func normalizeOptionalNodeAttrValues(name string, values []string) ([]string, error) {
	if len(values) == 0 {
		return nil, nil
	}
	return normalizeNodeAttrValues(name, values)
}

func normalizeNodeAttrValues(name string, values []string) ([]string, error) {
	if len(values) == 0 {
		return nil, fmt.Errorf("nodeattr requires at least one --%s", name)
	}
	result := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			return nil, fmt.Errorf("nodeattr --%s must not be empty", name)
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result, nil
}

func normalizeNodeAttrPools(values []string) ([]string, error) {
	if len(values) == 0 {
		return nil, nil
	}
	result := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			return nil, errors.New("nodeattr --ip-pool must not be empty")
		}
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return nil, fmt.Errorf("nodeattr IP pool %q is not a CIDR prefix: %w", value, err)
		}
		// Canonicalize like NormalizeIPSetCIDR and NormalizeAutoApproverRoute:
		// two spellings of one network must not author two pool entries.
		value = prefix.Masked().String()
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result, nil
}

func nodeAttrTargetKey(target []string) string {
	canonical := slices.Clone(target)
	slices.Sort(canonical)
	canonical = slices.Compact(canonical)
	return strings.Join(canonical, "\x00")
}

func nodeAttrEditField(spec NodeAttrSpec) string {
	if len(spec.Attr) != 0 {
		return nodeAttrAttrKey
	}
	return nodeAttrIPPoolKey
}

func nodeAttrEditValues(spec NodeAttrSpec) []string {
	if len(spec.Attr) != 0 {
		return spec.Attr
	}
	return spec.IPPool
}

func existingField(entry nodeAttrGrant, field string) []string {
	if field == nodeAttrAttrKey {
		return entry.Attr
	}
	return entry.IPPool
}

// nodeAttrMissing narrows wanted to the values entry does not already carry in
// field. It filters in place, so callers pass a clone and reassign the result;
// chaining it across every matching entry is what makes an add see a value that
// is in effect under the target set but lives in a later entry.
func nodeAttrMissing(entry nodeAttrGrant, field string, wanted []string) []string {
	existing := existingField(entry, field)
	return slices.DeleteFunc(wanted, func(value string) bool {
		return slices.ContainsFunc(existing, func(current string) bool {
			return nodeAttrValuesEqual(field, current, value)
		})
	})
}

func nodeAttrValueIndexes(field string, existing, wanted []string) []int {
	var indexes []int
	for index, current := range existing {
		if slices.ContainsFunc(wanted, func(value string) bool {
			return nodeAttrValuesEqual(field, current, value)
		}) {
			indexes = append(indexes, index)
		}
	}
	return indexes
}

func nodeAttrValuesEqual(field, left, right string) bool {
	if field != nodeAttrIPPoolKey {
		return left == right
	}
	leftPrefix, leftErr := netip.ParsePrefix(left)
	rightPrefix, rightErr := netip.ParsePrefix(right)
	if leftErr == nil && rightErr == nil {
		return leftPrefix.Masked() == rightPrefix.Masked()
	}
	return left == right
}

func nodeAttrEntryEmptyAfter(entry nodeAttrGrant, removedField string) bool {
	if removedField == nodeAttrAttrKey {
		return len(entry.IPPool) == 0 && len(entry.App) == 0
	}
	return len(entry.Attr) == 0 && len(entry.App) == 0
}

// nodeAttrGrant is read through the pinned schema, but new patch values are
// local maps above. That distinction keeps app data read-only and prevents an
// edit from marshaling and replacing the whole nodeAttrs section.
type nodeAttrGrant = tailscale.NodeAttrGrant
