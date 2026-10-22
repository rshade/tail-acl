package aclpolicy

import (
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"sort"
	"strings"

	"github.com/rshade/tailscale-utils/policycore"
)

// DefinitionKind identifies one of the policy's string-list maps that has a
// typed editor. The maps share their edit mechanics, but their values have
// different policy syntax and validation rules.
type DefinitionKind string

const (
	DefinitionGroup DefinitionKind = "group"
	DefinitionIPSet DefinitionKind = "ipset"
)

const (
	groupPrefix         = "group:"
	ipsetPrefix         = "ipset:"
	definitionGroupsKey = "groups"
	definitionIPSetsKey = "ipsets"
)

// DefinitionEdit describes a comment-preserving edit to groups or ipsets.
// Callers apply Operations with WritePatch after loading the typed policy.
type DefinitionEdit struct {
	Operations []PatchOperation
	Name       string
	Existed    bool
}

// Changed reports whether the edit has a value operation to apply. A caller
// may still append a comment-only operation for an existing definition.
func (e DefinitionEdit) Changed() bool { return len(e.Operations) != 0 }

// NormalizeGroupName validates a local group definition name. Local groups
// are distinct from SCIM groups, whose control-plane membership is outside the
// scope of this static authoring command.
func NormalizeGroupName(name string) (string, error) {
	return normalizeDefinitionName(name, groupPrefix)
}

// NormalizeIPSetName validates an ipset definition name.
func NormalizeIPSetName(name string) (string, error) {
	return normalizeDefinitionName(name, ipsetPrefix)
}

func normalizeDefinitionName(name, prefix string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", fmt.Errorf("%s name must not be empty", strings.TrimSuffix(prefix, ":"))
	}
	if !strings.HasPrefix(name, prefix) {
		return "", fmt.Errorf("%s name %q must have the %s prefix", strings.TrimSuffix(prefix, ":"), name, prefix)
	}
	if strings.TrimSpace(strings.TrimPrefix(name, prefix)) == "" {
		return "", fmt.Errorf("%s name %q is missing a name after %s", strings.TrimSuffix(prefix, ":"), name, prefix)
	}
	return name, nil
}

// ValidateGroupMember accepts the identity forms a static policy can author:
// login names and autogroups. It deliberately does not consult the control
// plane to verify that a login exists.
func ValidateGroupMember(member string) error {
	member = strings.TrimSpace(member)
	if member == "" {
		return errors.New("group member must not be empty")
	}
	if strings.HasPrefix(member, "autogroup:") && len(member) > len("autogroup:") {
		return nil
	}
	if policycore.LooksLikeUser(member) {
		return nil
	}
	return fmt.Errorf("group member %q is not a login or autogroup", member)
}

// NormalizeIPSetCIDR validates and canonicalizes one ipset member. Masking
// host bits makes equivalent CIDR spellings idempotent and avoids authoring
// duplicate entries that name the same network.
func NormalizeIPSetCIDR(cidr string) (string, error) {
	cidr = strings.TrimSpace(cidr)
	if cidr == "" {
		return "", errors.New("ipset CIDR must not be empty")
	}
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return "", fmt.Errorf("ipset member %q is not a CIDR prefix: %w", cidr, err)
	}
	return prefix.Masked().String(), nil
}

// IPSetMemberSpec is one requested ipset member together with how it was
// authored. CIDROnly marks a value from --cidr, which accepts only the CIDR
// prefix form it always has, so an existing invocation keeps its exact
// canonicalization and error text; a --member value takes the full grammar.
type IPSetMemberSpec struct {
	Value    string
	CIDROnly bool
}

// AddDefinition adds every absent member to a group or ipset. Existing
// members are preserved and duplicate requested members are collapsed in
// argument order, so repeating the command is a no-op. An ipset routes
// through AddIPSetMembers with every member CIDR-only.
func AddDefinition(policy *Policy, kind DefinitionKind, name string, members []string) (DefinitionEdit, error) {
	switch kind {
	case DefinitionIPSet:
		specs := make([]IPSetMemberSpec, 0, len(members))
		for _, member := range members {
			specs = append(specs, IPSetMemberSpec{Value: member, CIDROnly: true})
		}
		return AddIPSetMembers(policy, name, specs)
	case DefinitionGroup:
		group, logins, err := validateGroupEdit(name, members)
		if err != nil {
			return DefinitionEdit{}, err
		}
		missing := missingDefinitionMembers(kind, policy.Groups[group], logins)
		return definitionAddEdit(policy.Groups, definitionGroupsKey, group, missing), nil
	default:
		return DefinitionEdit{}, fmt.Errorf("unsupported definition kind %q", kind)
	}
}

// AddIPSetMembers adds every absent member to an ipset, accepting each form
// the control plane does. A --member value is validated against the policy in
// hand: a host: alias must be defined, an ipset: reference must name another
// existing ipset, and a reference that would close a cycle through the
// existing definitions is refused naming the path. The explicit-operation
// rule is checked on the set the command would write — existing members
// followed by the new ones — after idempotence filtering, so an already
// applied command stays a no-op.
func AddIPSetMembers(policy *Policy, name string, members []IPSetMemberSpec) (DefinitionEdit, error) {
	name, err := NormalizeIPSetName(name)
	if err != nil {
		return DefinitionEdit{}, err
	}
	if len(members) == 0 {
		return DefinitionEdit{}, fmt.Errorf("%s add requires at least one member", DefinitionIPSet)
	}
	validated := make([]string, 0, len(members))
	seen := make(map[string]struct{}, len(members))
	for _, spec := range members {
		var member string
		if spec.CIDROnly {
			member, err = NormalizeIPSetCIDR(spec.Value)
		} else {
			member, err = normalizeIPSetMember(policy, name, spec.Value)
		}
		if err != nil {
			return DefinitionEdit{}, err
		}
		if _, duplicate := seen[member]; duplicate {
			continue
		}
		seen[member] = struct{}{}
		validated = append(validated, member)
	}
	existing := policy.IPSets[name]
	missing := missingDefinitionMembers(DefinitionIPSet, existing, validated)
	if len(missing) != 0 {
		if err = policycore.ValidateIPSetOperations(slices.Concat(existing, missing)); err != nil {
			return DefinitionEdit{}, err
		}
	}
	return definitionAddEdit(policy.IPSets, definitionIPSetsKey, name, missing), nil
}

// normalizeIPSetMember parses one --member value and checks the references
// it makes against the policy, returning the canonical spelling to write.
func normalizeIPSetMember(policy *Policy, name, value string) (string, error) {
	member, err := policycore.ParseIPSetMember(value)
	if err != nil {
		return "", err
	}
	value = strings.TrimSpace(value)
	if alias, ok := member.HostAlias(); ok {
		if _, defined := policy.Hosts[alias]; !defined {
			return "", fmt.Errorf("ipset member %q names host alias %q, which is not defined in hosts", value, alias)
		}
	}
	if member.Kind == policycore.IPSetMemberIPSet {
		if member.Target == name {
			return "", fmt.Errorf("ipset member %q references %s itself", value, name)
		}
		if _, defined := policy.IPSets[member.Target]; !defined {
			return "", fmt.Errorf("ipset member %q references %s, which is not defined in ipsets", value, member.Target)
		}
		if path := ipsetReferencePath(policy.IPSets, member.Target, name, make(map[string]bool)); path != nil {
			return "", fmt.Errorf("ipset member %q creates a cycle: %s", value,
				strings.Join(append([]string{name}, path...), " -> "))
		}
	}
	return member.String(), nil
}

// ipsetReferencePath walks from one ipset through the ipset: members of the
// existing definitions looking for target, returning the path of names from
// from to target inclusive, or nil when target is unreachable. Members that
// do not parse are skipped: a hand-written malformed member is a lint
// concern, not a reason to refuse an unrelated add.
func ipsetReferencePath(ipsets map[string][]string, from, target string, visited map[string]bool) []string {
	if from == target {
		return []string{from}
	}
	if visited[from] {
		return nil
	}
	visited[from] = true
	for _, raw := range ipsets[from] {
		member, err := policycore.ParseIPSetMember(raw)
		if err != nil || member.Kind != policycore.IPSetMemberIPSet {
			continue
		}
		if path := ipsetReferencePath(ipsets, member.Target, target, visited); path != nil {
			return append([]string{from}, path...)
		}
	}
	return nil
}

// definitionAddEdit builds the patch that appends missing to name, creating
// the map or the definition as needed.
func definitionAddEdit(definitions map[string][]string, topLevel, name string, missing []string) DefinitionEdit {
	existing, existed := definitions[name]
	edit := DefinitionEdit{Name: name, Existed: existed}
	if len(missing) == 0 {
		return edit
	}

	switch {
	case definitions == nil:
		edit.Operations = append(edit.Operations, PatchAdd(
			map[string][]string{name: missing}, topLevel))
	case existing == nil:
		// Either the key is absent, or it is present with a null value, which
		// decodes to a nil slice and cannot be appended into. RFC 6902 add
		// replaces an existing member, so one operation serves both. Existed
		// keeps tracking map presence, because a null-valued member is still a
		// comment target that already exists.
		edit.Operations = append(edit.Operations, PatchAdd(
			missing, topLevel, name))
	default:
		for _, member := range missing {
			edit.Operations = append(edit.Operations, PatchAdd(
				member, topLevel, name, "-"))
		}
	}
	return edit
}

// RemoveDefinition removes a whole group or ipset definition. A referenced
// definition is refused unless force is true, because otherwise the command
// would manufacture the undefined-reference finding that it is meant to
// remediate.
func RemoveDefinition(policy *Policy, kind DefinitionKind, name string, force bool) (DefinitionEdit, error) {
	name, err := normalizeDefinitionNameForKind(kind, name)
	if err != nil {
		return DefinitionEdit{}, err
	}
	definitions, topLevel, err := definitionMap(policy, kind)
	if err != nil {
		return DefinitionEdit{}, err
	}
	if _, exists := definitions[name]; !exists {
		return DefinitionEdit{Name: name}, nil
	}
	if references := DefinitionReferences(policy, name); len(references) != 0 && !force {
		return DefinitionEdit{}, &DefinitionReferenceError{
			Kind:       kind,
			Name:       name,
			References: references,
		}
	}
	return DefinitionEdit{
		Name:    name,
		Existed: true,
		Operations: []PatchOperation{
			PatchRemove(topLevel, name),
		},
	}, nil
}

// DefinitionReferenceError explains why a safe definition removal was
// refused. References are sorted for stable human and machine diagnostics.
type DefinitionReferenceError struct {
	Kind       DefinitionKind
	Name       string
	References []string
}

func (e *DefinitionReferenceError) Error() string {
	return fmt.Sprintf("cannot remove %s %s: referenced at %s; use --force to override",
		e.Kind, e.Name, strings.Join(e.References, ", "))
}

func validateGroupEdit(name string, members []string) (string, []string, error) {
	name, err := NormalizeGroupName(name)
	if err != nil {
		return "", nil, err
	}
	if len(members) == 0 {
		return "", nil, fmt.Errorf("%s add requires at least one member", DefinitionGroup)
	}
	validated := make([]string, 0, len(members))
	seen := make(map[string]struct{}, len(members))
	for _, member := range members {
		member = strings.TrimSpace(member)
		if err = ValidateGroupMember(member); err != nil {
			return "", nil, err
		}
		if _, duplicate := seen[member]; duplicate {
			continue
		}
		seen[member] = struct{}{}
		validated = append(validated, member)
	}
	return name, validated, nil
}

func normalizeDefinitionNameForKind(kind DefinitionKind, name string) (string, error) {
	switch kind {
	case DefinitionGroup:
		return NormalizeGroupName(name)
	case DefinitionIPSet:
		return NormalizeIPSetName(name)
	default:
		return "", fmt.Errorf("unsupported definition kind %q", kind)
	}
}

func definitionMap(policy *Policy, kind DefinitionKind) (map[string][]string, string, error) {
	switch kind {
	case DefinitionGroup:
		return policy.Groups, definitionGroupsKey, nil
	case DefinitionIPSet:
		return policy.IPSets, definitionIPSetsKey, nil
	default:
		return nil, "", fmt.Errorf("unsupported definition kind %q", kind)
	}
}

func missingDefinitionMembers(kind DefinitionKind, existing, wanted []string) []string {
	missing := make([]string, 0, len(wanted))
	for _, member := range wanted {
		if !slices.ContainsFunc(existing, func(current string) bool {
			return definitionMembersEqual(kind, current, member)
		}) {
			missing = append(missing, member)
		}
	}
	return missing
}

// definitionMembersEqual compares two members by identity. An ipset member is
// compared in its canonical spelling so two spellings of one network, range,
// or operation cannot author two entries; a member that does not parse is
// compared as written.
func definitionMembersEqual(kind DefinitionKind, left, right string) bool {
	if kind != DefinitionIPSet {
		return left == right
	}
	return canonicalIPSetMember(left) == canonicalIPSetMember(right)
}

func canonicalIPSetMember(member string) string {
	if parsed, err := policycore.ParseIPSetMember(member); err == nil {
		return parsed.String()
	}
	return strings.TrimSpace(member)
}

// DefinitionReferences returns policy locations that name target. It mirrors
// the linter's reference walk, including nested group membership, node
// attribute targets, grant via-routers, and all authoring-relevant
// rule/test/approver forms, so safe removal cannot overlook a reference just
// because it lives outside grants.
//
// The two walks are kept in step deliberately: a field this misses is a
// definition removed without --force, and the same field missing from
// collectReferences is lint telling the operator to remove it.
//
//nolint:gocognit,funlen // one safety walk intentionally covers every reference-bearing policy field.
func DefinitionReferences(policy *Policy, target string) []string {
	var references []string
	add := func(locator string, values []string, destination bool) {
		for index, value := range values {
			if destination {
				value = destinationHost(value)
			} else {
				value = strings.TrimSpace(value)
			}
			if value == target {
				references = append(references, fmt.Sprintf("%s[%d]", locator, index))
			}
		}
	}
	addScalar := func(locator, value string, destination bool) {
		if destination {
			value = destinationHost(value)
		} else {
			value = strings.TrimSpace(value)
		}
		if value == target {
			references = append(references, locator)
		}
	}

	for index, grant := range policy.Grants {
		add(fmt.Sprintf("grants[%d].%s", index, policySourceField), grant.Source, false)
		// Grant destinations are node selectors and are portless; a selector
		// such as ipset:office must not be mistaken for host "ipset".
		add(fmt.Sprintf("grants[%d].%s", index, policyDestinationField), grant.Destination, false)
		add(fmt.Sprintf("grants[%d].via", index), grant.Via, false)
	}
	for index, attr := range policy.NodeAttrs {
		add(fmt.Sprintf("nodeAttrs[%d].target", index), attr.Target, false)
		for appName, apps := range attr.App {
			for appIndex, app := range apps {
				if app == nil {
					continue
				}
				add(fmt.Sprintf("nodeAttrs[%d].app[%q][%d].connectors", index, appName, appIndex),
					app.Connectors, false)
			}
		}
	}
	for index, entry := range policy.ACLs {
		sources, sourceField := entry.Source, policySourceField
		if len(sources) == 0 {
			sources, sourceField = entry.Users, "users"
		}
		destinations, destinationField := entry.Destination, policyDestinationField
		if len(destinations) == 0 {
			destinations, destinationField = entry.Ports, "ports"
		}
		add(fmt.Sprintf("acls[%d].%s", index, sourceField), sources, false)
		add(fmt.Sprintf("acls[%d].%s", index, destinationField), destinations, true)
	}
	for name, members := range policy.Groups {
		add("groups["+name+"]", members, false)
	}
	for name, members := range policy.IPSets {
		for index, member := range members {
			if referenced, ok := ipsetMemberReference(member); ok && referenced == target {
				references = append(references, fmt.Sprintf("ipsets[%s][%d]", name, index))
			}
		}
	}
	for name, owners := range policy.TagOwners {
		add("tagOwners["+name+"]", owners, false)
	}
	if autoApprovers := policy.AutoApprovers; autoApprovers != nil {
		for route, approvers := range autoApprovers.Routes {
			add("autoApprovers.routes["+route+"]", approvers, false)
		}
		add("autoApprovers.exitNode", autoApprovers.ExitNode, false)
		for service, approvers := range autoApprovers.Services {
			add("autoApprovers.services["+service+"]", approvers, false)
		}
	}
	for index, test := range policy.Tests {
		source, sourceField := test.Source, policySourceField
		if source == "" {
			source, sourceField = test.User, "user"
		}
		addScalar(fmt.Sprintf("tests[%d].%s", index, sourceField), source, false)
		accept, acceptField := test.Accept, string(TestAccept)
		if len(accept) == 0 {
			accept, acceptField = test.Allow, "allow"
		}
		add(fmt.Sprintf("tests[%d].%s", index, acceptField), accept, true)
		add(fmt.Sprintf("tests[%d].deny", index), test.Deny, true)
	}
	for index, rule := range policy.SSH {
		add(fmt.Sprintf("ssh[%d].%s", index, policySourceField), rule.Source, false)
		add(fmt.Sprintf("ssh[%d].%s", index, policyDestinationField), rule.Destination, false)
		add(fmt.Sprintf("ssh[%d].recorder", index), rule.Recorder, false)
	}
	for index, test := range policy.SSHTests {
		addScalar(fmt.Sprintf("sshTests[%d].%s", index, policySourceField), test.Source, false)
		add(fmt.Sprintf("sshTests[%d].%s", index, policyDestinationField), test.Destination, false)
	}
	// Same field collectReferences reads. A definition named only here is in
	// use, so removal without --force must refuse it.
	for _, alias := range slices.Sorted(maps.Keys(policy.ExternalTailnets)) {
		add(fmt.Sprintf("externalTailnets[%s].allowExternalReferencesTo", alias),
			policy.ExternalTailnets[alias].AllowExternalReferencesTo, false)
	}

	sort.Strings(references)
	return slices.Compact(references)
}

// ipsetMemberReference reports the definition an ipset member names: the
// ipset: target as written, or the alias behind a host: target, either bare
// or under an add/remove operation. A literal member names no definition, and
// neither does one that does not parse.
func ipsetMemberReference(member string) (string, bool) {
	parsed, err := policycore.ParseIPSetMember(member)
	if err != nil {
		return "", false
	}
	if parsed.Kind == policycore.IPSetMemberIPSet {
		return parsed.Target, true
	}
	return parsed.HostAlias()
}
