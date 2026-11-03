package aclpolicy

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"unicode"

	tailscale "tailscale.com/client/tailscale/v2"

	"github.com/rshade/tail-acl/pkg/policycore/alpha"
)

const externalTailnetsKey = "externalTailnets"

// ExternalTailnetSpec is one alias an authoring command wants in externalTailnets.
type ExternalTailnetSpec struct {
	Alias                     string
	ExternalID                string
	AllowIncomingConnections  bool
	AllowExternalReferencesTo []string
}

// ExternalTailnetEdit is a comment-preserving edit of one externalTailnets entry.
type ExternalTailnetEdit struct {
	Operations []PatchOperation
	Alias      string
	Existed    bool
}

// Changed reports whether the edit writes a value.
func (e ExternalTailnetEdit) Changed() bool { return len(e.Operations) != 0 }

// ExternalTailnetEntry is one alias as list reports it.
type ExternalTailnetEntry struct {
	Alias                     string   `json:"alias"`
	ExternalID                string   `json:"external_id"`
	AllowIncomingConnections  bool     `json:"allow_incoming_connections"`
	AllowExternalReferencesTo []string `json:"allow_external_references_to,omitempty"`
}

// ExternalTailnetReferenceError explains why a safe alias removal was refused.
type ExternalTailnetReferenceError struct {
	Alias      string
	References []string
}

func (e *ExternalTailnetReferenceError) Error() string {
	return fmt.Sprintf(
		"cannot remove external tailnet %s: referenced at %s; use --force to override",
		e.Alias, strings.Join(e.References, ", "),
	)
}

// AddExternalTailnet inserts or replaces one alias. An entry that already
// matches the spec produces no operations, so repeating the command is a no-op.
func AddExternalTailnet(policy *Policy, spec ExternalTailnetSpec) (ExternalTailnetEdit, error) {
	alias, err := normalizeExternalAlias(spec.Alias)
	if err != nil {
		return ExternalTailnetEdit{}, err
	}
	externalID, err := normalizeExternalID(spec.ExternalID)
	if err != nil {
		return ExternalTailnetEdit{}, err
	}
	allow, err := normalizeAllowExternalReferences(spec.AllowExternalReferencesTo)
	if err != nil {
		return ExternalTailnetEdit{}, err
	}
	desired := tailscale.ExternalTailnet{
		ExternalID:                externalID,
		AllowIncomingConnections:  spec.AllowIncomingConnections,
		AllowExternalReferencesTo: allow,
	}
	edit := ExternalTailnetEdit{Alias: alias}
	if policy.ExternalTailnets == nil {
		edit.Operations = []PatchOperation{PatchAdd(
			map[string]tailscale.ExternalTailnet{alias: desired}, externalTailnetsKey,
		)}
		return edit, nil
	}
	existing, existed := policy.ExternalTailnets[alias]
	edit.Existed = existed
	if existed && sameExternalTailnet(existing, desired) {
		return edit, nil
	}
	edit.Operations = []PatchOperation{PatchAdd(desired, externalTailnetsKey, alias)}
	return edit, nil
}

// RemoveExternalTailnet removes one alias. A selector that still names the
// alias is refused unless force is set. A missing alias is a no-op.
func RemoveExternalTailnet(policy *Policy, alias string, force bool) (ExternalTailnetEdit, error) {
	alias, err := normalizeExternalAlias(alias)
	if err != nil {
		return ExternalTailnetEdit{}, err
	}
	edit := ExternalTailnetEdit{Alias: alias}
	if _, exists := policy.ExternalTailnets[alias]; !exists {
		return edit, nil
	}
	edit.Existed = true
	if !force {
		if references := ExternalTailnetReferences(policy, alias); len(references) != 0 {
			return ExternalTailnetEdit{}, &ExternalTailnetReferenceError{
				Alias: alias, References: references,
			}
		}
	}
	edit.Operations = []PatchOperation{PatchRemove(externalTailnetsKey, alias)}
	return edit, nil
}

// ListExternalTailnets returns aliases in lexical order.
func ListExternalTailnets(policy *Policy) []ExternalTailnetEntry {
	if len(policy.ExternalTailnets) == 0 {
		return []ExternalTailnetEntry{}
	}
	aliases := make([]string, 0, len(policy.ExternalTailnets))
	for alias := range policy.ExternalTailnets {
		aliases = append(aliases, alias)
	}
	slices.Sort(aliases)
	entries := make([]ExternalTailnetEntry, 0, len(aliases))
	for _, alias := range aliases {
		declaration := policy.ExternalTailnets[alias]
		entries = append(entries, ExternalTailnetEntry{
			Alias:                     alias,
			ExternalID:                declaration.ExternalID,
			AllowIncomingConnections:  declaration.AllowIncomingConnections,
			AllowExternalReferencesTo: declaration.AllowExternalReferencesTo,
		})
	}
	return entries
}

// ExternalTailnetReferences returns selectors that name alias via group:// or
// tag://. Locations match the alias-unknown lint, so a removal cannot leave
// a reference that lint would then call unknown.
func ExternalTailnetReferences(policy *Policy, alias string) []string {
	references := slices.Concat(
		externalGrantAliasReferences(policy.Grants, alias),
		externalACLAliasReferences(policy.ACLs, alias),
		externalSSHAliasReferences(policy.SSH, alias),
		externalTestAliasReferences(policy.Tests, alias),
		externalSSHTestAliasReferences(policy.SSHTests, alias),
		externalAutoApproverAliasReferences(policy.AutoApprovers, alias),
	)
	slices.Sort(references)
	return slices.Compact(references)
}

func externalGrantAliasReferences(grants []tailscale.Grant, alias string) []string {
	var references []string
	for index, grant := range grants {
		references = appendLocatedAliases(
			references, fmt.Sprintf("grants[%d].%s", index, policySourceField), grant.Source, alias,
		)
		references = appendLocatedAliases(
			references, fmt.Sprintf("grants[%d].%s", index, policyDestinationField), grant.Destination, alias,
		)
	}
	return references
}

func externalACLAliasReferences(entries []tailscale.ACLEntry, alias string) []string {
	var references []string
	for index, entry := range entries {
		sources, sourceField := entry.Source, policySourceField
		if len(sources) == 0 {
			sources, sourceField = entry.Users, policyUsersField
		}
		destinations, destinationField := entry.Destination, policyDestinationField
		if len(destinations) == 0 {
			destinations, destinationField = entry.Ports, policyPortsField
		}
		references = appendLocatedAliases(
			references, fmt.Sprintf("acls[%d].%s", index, sourceField), sources, alias,
		)
		references = appendLocatedAliases(
			references, fmt.Sprintf("acls[%d].%s", index, destinationField), destinations, alias,
		)
	}
	return references
}

func externalSSHAliasReferences(rules []SSHRule, alias string) []string {
	var references []string
	for index, rule := range rules {
		references = appendLocatedAliases(
			references, fmt.Sprintf("ssh[%d].%s", index, policySourceField), rule.Source, alias,
		)
		references = appendLocatedAliases(
			references, fmt.Sprintf("ssh[%d].%s", index, policyDestinationField), rule.Destination, alias,
		)
		references = appendLocatedAliases(
			references, fmt.Sprintf("ssh[%d].recorder", index), rule.Recorder, alias,
		)
	}
	return references
}

func externalTestAliasReferences(tests []tailscale.ACLTest, alias string) []string {
	var references []string
	for index, test := range tests {
		source, sourceField := test.Source, policySourceField
		if source == "" {
			source, sourceField = test.User, "user"
		}
		references = appendLocatedAlias(
			references, fmt.Sprintf("tests[%d].%s", index, sourceField), source, alias,
		)
		accept, acceptField := test.Accept, "accept"
		if len(accept) == 0 {
			accept, acceptField = test.Allow, "allow"
		}
		references = appendLocatedAliases(
			references, fmt.Sprintf("tests[%d].%s", index, acceptField), accept, alias,
		)
		references = appendLocatedAliases(
			references, fmt.Sprintf("tests[%d].deny", index), test.Deny, alias,
		)
	}
	return references
}

func externalSSHTestAliasReferences(tests []SSHTest, alias string) []string {
	var references []string
	for index, test := range tests {
		references = appendLocatedAlias(
			references, fmt.Sprintf("sshTests[%d].%s", index, policySourceField), test.Source, alias,
		)
		references = appendLocatedAliases(
			references, fmt.Sprintf("sshTests[%d].%s", index, policyDestinationField), test.Destination, alias,
		)
	}
	return references
}

func externalAutoApproverAliasReferences(approvers *tailscale.ACLAutoApprovers, alias string) []string {
	if approvers == nil {
		return nil
	}
	references := appendLocatedAliases(nil, "autoApprovers.exitNode", approvers.ExitNode, alias)
	for route, values := range approvers.Routes {
		references = appendLocatedAliases(references, "autoApprovers.routes["+route+"]", values, alias)
	}
	for service, values := range approvers.Services {
		references = appendLocatedAliases(references, "autoApprovers.services["+service+"]", values, alias)
	}
	return references
}

func appendLocatedAliases(references []string, locator string, values []string, alias string) []string {
	for index, value := range values {
		references = appendLocatedAlias(references, fmt.Sprintf("%s[%d]", locator, index), value, alias)
	}
	return references
}

func appendLocatedAlias(references []string, locator, value, alias string) []string {
	if selectorNamesExternalAlias(value, alias) {
		return append(references, locator)
	}
	return references
}

func selectorNamesExternalAlias(selector, alias string) bool {
	selector = strings.TrimSpace(selector)
	if !alpha.LooksLikeExternalSelector(selector) {
		return false
	}
	parsed, err := alpha.ParseExternalSelector(selector)
	return err == nil && parsed.Alias == alias
}

func sameExternalTailnet(left, right tailscale.ExternalTailnet) bool {
	return left.ExternalID == right.ExternalID &&
		left.AllowIncomingConnections == right.AllowIncomingConnections &&
		slices.Equal(left.AllowExternalReferencesTo, right.AllowExternalReferencesTo)
}

func normalizeExternalAlias(alias string) (string, error) {
	alias = strings.TrimSpace(alias)
	if alias == "" {
		return "", errors.New("external tailnet alias must not be empty")
	}
	if strings.Contains(alias, "/") || strings.Contains(alias, ":") {
		return "", fmt.Errorf("external tailnet alias %q must not contain '/' or ':'", alias)
	}
	if strings.ContainsFunc(alias, badTokenRune) {
		return "", fmt.Errorf(
			"external tailnet alias %q contains whitespace or a non-printable character", alias,
		)
	}
	return alias, nil
}

func normalizeExternalID(externalID string) (string, error) {
	externalID = strings.TrimSpace(externalID)
	if externalID == "" {
		return "", errors.New("external id must not be empty")
	}
	if strings.ContainsFunc(externalID, badTokenRune) {
		return "", fmt.Errorf("external id %q contains whitespace or a non-printable character", externalID)
	}
	return externalID, nil
}

func normalizeAllowExternalReferences(refs []string) ([]string, error) {
	if len(refs) == 0 {
		return nil, nil
	}
	allowed := make([]string, 0, len(refs))
	seen := make(map[string]struct{}, len(refs))
	for _, ref := range refs {
		ref = strings.TrimSpace(ref)
		switch {
		case ref == "":
			return nil, errors.New("allow-external-references-to value must not be empty")
		case strings.HasPrefix(ref, "group://"), strings.HasPrefix(ref, "tag://"):
			return nil, fmt.Errorf(
				"allow-external-references-to %q must be a local group: or tag: selector", ref,
			)
		case strings.HasPrefix(ref, "group:"), strings.HasPrefix(ref, "tag:"):
		default:
			return nil, fmt.Errorf(
				"allow-external-references-to %q must be a local group: or tag: selector", ref,
			)
		}
		name := ref[strings.IndexByte(ref, ':')+1:]
		if name == "" || strings.ContainsFunc(ref, badTokenRune) {
			return nil, fmt.Errorf("allow-external-references-to %q is not a selector", ref)
		}
		if _, duplicate := seen[ref]; duplicate {
			continue
		}
		seen[ref] = struct{}{}
		allowed = append(allowed, ref)
	}
	return allowed, nil
}

func badTokenRune(r rune) bool {
	return unicode.IsSpace(r) || !unicode.IsPrint(r)
}
