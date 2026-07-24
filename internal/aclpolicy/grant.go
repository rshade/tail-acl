package aclpolicy

import (
	"encoding/json"
	"fmt"
	"slices"

	tailscale "tailscale.com/client/tailscale/v2"
)

// GrantSemanticKey canonicalizes a grant so two grants that differ only in the
// order of their selector lists produce the same key. Selector lists are
// treated as sets; JSON encoding folds omitted and explicitly empty optional
// fields together through the Grant type's omitempty tags. It is shared by the
// grant-add idempotency check and the lint duplicate-grant check so both agree
// on what "the same grant" means.
func GrantSemanticKey(grant tailscale.Grant) (string, error) {
	grant.Source = sortedStrings(grant.Source)
	grant.Destination = sortedStrings(grant.Destination)
	grant.IP = sortedStrings(grant.IP)
	grant.SrcPosture = sortedStrings(grant.SrcPosture)
	grant.Via = sortedStrings(grant.Via)

	encoded, err := json.Marshal(grant)
	if err != nil {
		return "", fmt.Errorf("canonicalizing grant: %w", err)
	}
	return string(encoded), nil
}

func sortedStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	sorted := slices.Clone(values)
	slices.Sort(sorted)
	return sorted
}
