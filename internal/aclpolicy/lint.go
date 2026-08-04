package aclpolicy

import (
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"

	tailscale "tailscale.com/client/tailscale/v2"

	"github.com/rshade/tailscale-utils/policycore"
)

// LintSeverity ranks a lint finding. info < warn < error.
type LintSeverity string

const (
	// LintInfo is hygiene worth surfacing but not a defect (e.g. an unused
	// definition).
	LintInfo LintSeverity = "info"
	// LintWarn is a likely mistake that does not necessarily break the policy
	// (e.g. an over-broad wildcard or a dead grant).
	LintWarn LintSeverity = "warn"
	// LintError is a reference the policy cannot satisfy (e.g. an undefined tag
	// or a destination tag no one owns).
	LintError LintSeverity = "error"
)

// Lint finding IDs. Each is a stable, machine-consumable identifier for one
// class of static policy-hygiene problem.
const (
	LintUndefinedReference = "undefined-reference"
	LintDstTagNoOwner      = "dst-tag-no-owner"
	LintOverbroadWildcard  = "overbroad-wildcard"
	LintGrantEmpty         = "grant-empty"
	LintDuplicateGrant     = "duplicate-grant"
	LintUnusedTag          = "unused-tag"
	LintUnusedGroup        = "unused-group"
	LintUnusedHost         = "unused-host"
	LintUnusedIPSet        = "unused-ipset"
)

// WildcardPolicy controls how strictly the overbroad-wildcard check treats "*".
type WildcardPolicy string

const (
	// WildcardAnyToAny flags only a rule whose source and destination are both
	// "*" — the genuinely dangerous any-to-any grant. A standalone "*" on one
	// side is common and legitimate, so it is allowed. This is the default.
	WildcardAnyToAny WildcardPolicy = "any-to-any"
	// WildcardAny flags any "*" appearing in a rule's source or destination.
	WildcardAny WildcardPolicy = "any"
	// WildcardOff disables the overbroad-wildcard check.
	WildcardOff WildcardPolicy = "off"
)

// Severity ranks, ordered so a higher rank is more severe.
const (
	rankInfo = iota
	rankWarn
	rankError
)

// rankUnknown sorts below everything so an unrecognized severity never
// satisfies a threshold.
const rankUnknown = -1

// Locator field names, kept as constants (with the leading dot) so the "acls[i]"
// and "grants[i]" locators share one spelling.
const (
	fieldSrc   = ".src"
	fieldUsers = ".users"
	fieldDst   = ".dst"
	fieldPorts = ".ports"
)

func lintSeverityRank(s LintSeverity) int {
	switch s {
	case LintInfo:
		return rankInfo
	case LintWarn:
		return rankWarn
	case LintError:
		return rankError
	default:
		return rankUnknown
	}
}

// AtLeast reports whether s is at least as severe as threshold.
func (s LintSeverity) AtLeast(threshold LintSeverity) bool {
	return lintSeverityRank(s) >= lintSeverityRank(threshold)
}

// ParseLintSeverity parses a severity name, reporting whether it was valid.
func ParseLintSeverity(value string) (LintSeverity, bool) {
	switch LintSeverity(value) {
	case LintInfo, LintWarn, LintError:
		return LintSeverity(value), true
	default:
		return "", false
	}
}

// ParseWildcardPolicy parses a wildcard-policy name, reporting whether it was
// valid.
func ParseWildcardPolicy(value string) (WildcardPolicy, bool) {
	switch WildcardPolicy(value) {
	case WildcardAnyToAny, WildcardAny, WildcardOff:
		return WildcardPolicy(value), true
	default:
		return "", false
	}
}

// LintFinding is one static-hygiene problem the linter found. Rule is a stable
// locator (e.g. "grants[2].dst[0]" or "tagOwners[tag:x]"); Trace is the decision
// path as data, mirroring the doctor and check/test classifiers so a human, an
// agent, and an audit all read the same reasoning.
type LintFinding struct {
	ID          string       `json:"id"`
	Severity    LintSeverity `json:"severity"`
	Rule        string       `json:"rule"`
	Value       string       `json:"value,omitempty"`
	Evidence    string       `json:"evidence"`
	Remediation string       `json:"remediation,omitempty"`
	Trace       []string     `json:"trace,omitempty"`
}

// LintSummary contains aggregate finding counts by severity.
type LintSummary struct {
	Total int `json:"total"`
	Error int `json:"error"`
	Warn  int `json:"warn"`
	Info  int `json:"info"`
}

// LintReport is the pure, deterministic result of statically linting a policy.
type LintReport struct {
	Findings []LintFinding `json:"findings"`
	Summary  LintSummary   `json:"summary"`
}

// CountAtLeast reports how many findings are at least as severe as threshold.
func (r LintReport) CountAtLeast(threshold LintSeverity) int {
	count := 0
	for _, finding := range r.Findings {
		if finding.Severity.AtLeast(threshold) {
			count++
		}
	}
	return count
}

// LintOptions configures EvaluateLint.
type LintOptions struct {
	// Wildcard selects how strictly "*" is flagged. The zero value is treated as
	// WildcardAnyToAny.
	Wildcard WildcardPolicy
}

// LintCheck describes one class of lint finding for the machine-readable schema.
type LintCheck struct {
	ID          string       `json:"id"`
	Severity    LintSeverity `json:"severity"`
	Description string       `json:"description"`
}

// LintCatalog returns the catalog of lint finding classes, so -schema can
// advertise the finding vocabulary the way tailscale-doctor advertises its
// checks — an agent reads it to learn what lint can report.
func LintCatalog() []LintCheck {
	return []LintCheck{
		{LintUndefinedReference, LintError, "a src/dst names a group/tag/ipset/host alias that is not defined"},
		{LintDstTagNoOwner, LintError, "a destination tag has no tagOwners entry, so no node can carry it"},
		{LintOverbroadWildcard, LintWarn, "an over-broad * selector (tuned by -wildcard)"},
		{LintGrantEmpty, LintWarn, "a grant has an empty required selector list and can never match"},
		{LintDuplicateGrant, LintWarn, "a grant is identical to an earlier one"},
		{LintUnusedTag, LintInfo, "a tag is defined but referenced by no rule"},
		{LintUnusedGroup, LintInfo, "a group is defined but referenced by no rule"},
		{LintUnusedHost, LintInfo, "a host alias is defined but referenced by no rule"},
		{LintUnusedIPSet, LintInfo, "an ipset is defined but referenced by no rule"},
	}
}

// EvaluateLint statically checks a policy for hygiene problems derivable from
// the policy alone — no control-plane access. It reports dead grants, undefined
// tag/group/host/ipset references, destination tags with no owner, over-broad
// wildcards, duplicate grants, and definitions referenced by nothing.
//
// It is deliberately node-blind: whether a definition is used by a real device
// is a control-plane coverage question that belongs to tailnet-audit, not here.
func EvaluateLint(policy *tailscale.ACL, opts LintOptions) (LintReport, error) {
	if policy == nil {
		return LintReport{}, errors.New("policy is nil")
	}
	return evaluateLint(policy, policy.SSH, nil, opts)
}

// EvaluatePolicyLint statically checks a loaded policy, including local schema
// extensions that the pinned Tailscale client does not expose.
func EvaluatePolicyLint(policy *Policy, opts LintOptions) (LintReport, error) {
	if policy == nil {
		return LintReport{}, errors.New("policy is nil")
	}
	// sshRules(), not policy.ACL.SSH: the mirror is only populated by Load, so
	// reading it here would silently under-report references for a Policy built
	// any other way.
	return evaluateLint(&policy.ACL, policy.sshRules(), policy.SSHTests, opts)
}

func evaluateLint(
	policy *tailscale.ACL,
	sshRules []tailscale.ACLSSH,
	sshTests []SSHTest,
	opts LintOptions,
) (LintReport, error) {
	if policy == nil {
		return LintReport{}, errors.New("policy is nil")
	}
	wildcard := opts.Wildcard
	if wildcard == "" {
		wildcard = WildcardAnyToAny
	}

	findings := make([]LintFinding, 0)
	findings = append(findings, lintGrants(policy, wildcard)...)
	findings = append(findings, lintACLs(policy, wildcard)...)
	findings = append(findings, lintSSHRules(policy, sshRules)...)
	findings = append(findings, lintSSHTests(policy, sshTests)...)
	duplicates, err := lintDuplicateGrants(policy)
	if err != nil {
		return LintReport{}, err
	}
	findings = append(findings, duplicates...)
	findings = append(findings, lintUnusedDefinitions(policy, sshRules, sshTests)...)

	// Sort into a stable order so the output is deterministic even though the
	// unused-definition checks iterate over maps.
	sort.SliceStable(findings, func(i, j int) bool {
		if findings[i].Rule != findings[j].Rule {
			return findings[i].Rule < findings[j].Rule
		}
		if findings[i].ID != findings[j].ID {
			return findings[i].ID < findings[j].ID
		}
		return findings[i].Value < findings[j].Value
	})

	report := LintReport{Findings: findings}
	for _, finding := range findings {
		report.Summary.Total++
		switch finding.Severity {
		case LintError:
			report.Summary.Error++
		case LintWarn:
			report.Summary.Warn++
		case LintInfo:
			report.Summary.Info++
		}
	}
	return report, nil
}

func lintGrants(policy *tailscale.ACL, wildcard WildcardPolicy) []LintFinding {
	findings := make([]LintFinding, 0)
	for index, grant := range policy.Grants {
		locator := fmt.Sprintf("grants[%d]", index)
		if empty := emptyGrantReason(grant); empty != "" {
			findings = append(findings, LintFinding{
				ID:          LintGrantEmpty,
				Severity:    LintWarn,
				Rule:        locator,
				Evidence:    "grant can never match: " + empty,
				Remediation: "populate the empty selector list, or remove the grant",
				Trace: []string{
					locator + " " + empty,
					"a grant with an empty required selector list matches no traffic",
				},
			})
		}
		findings = append(findings, wildcardFindings(
			locator, grant.Source, grant.Destination, wildcard)...)
		findings = append(findings, sourceReferenceFindings(policy, locator+fieldSrc, grant.Source)...)
		findings = append(findings, nodeDestinationReferenceFindings(policy, locator+fieldDst, grant.Destination)...)
	}
	return findings
}

func lintACLs(policy *tailscale.ACL, wildcard WildcardPolicy) []LintFinding {
	findings := make([]LintFinding, 0)
	for index, entry := range policy.ACLs {
		locator := fmt.Sprintf("acls[%d]", index)
		sources, sourceField := entry.Source, fieldSrc
		if len(sources) == 0 {
			sources, sourceField = entry.Users, fieldUsers
		}
		destinations, destinationField := entry.Destination, fieldDst
		if len(destinations) == 0 {
			destinations, destinationField = entry.Ports, fieldPorts
		}
		findings = append(findings, wildcardFindings(
			locator, sources, destinationHosts(destinations), wildcard)...)
		findings = append(findings, sourceReferenceFindings(policy, locator+sourceField, sources)...)
		findings = append(findings, destinationReferenceFindings(policy, locator+destinationField, destinations)...)
	}
	return findings
}

func lintSSHRules(policy *tailscale.ACL, rules []tailscale.ACLSSH) []LintFinding {
	findings := make([]LintFinding, 0)
	for index, rule := range rules {
		locator := fmt.Sprintf("ssh[%d]", index)
		findings = append(findings,
			sourceReferenceFindings(policy, locator+fieldSrc, rule.Source)...)
		findings = append(findings,
			nodeDestinationReferenceFindings(policy, locator+fieldDst, rule.Destination)...)
		// Recorder entries are node selectors, just like SSH destinations.
		findings = append(findings,
			nodeDestinationReferenceFindings(policy, locator+".recorder", rule.Recorder)...)
	}
	return findings
}

func lintSSHTests(policy *tailscale.ACL, tests []SSHTest) []LintFinding {
	findings := make([]LintFinding, 0)
	for index, test := range tests {
		locator := fmt.Sprintf("sshTests[%d]", index)
		if finding, ok := sourceReferenceFinding(policy, locator+fieldSrc, test.Source); ok {
			findings = append(findings, finding)
		}
		findings = append(findings,
			nodeDestinationReferenceFindings(policy, locator+fieldDst, test.Destination)...)
	}
	return findings
}

// emptyGrantReason reports why a grant can never match, or "" if it can. A grant
// with no App capability needs source, destination, and IP to match traffic; an
// App-only grant legitimately omits IP.
func emptyGrantReason(grant tailscale.Grant) string {
	switch {
	case len(grant.Source) == 0:
		return "src is empty"
	case len(grant.Destination) == 0:
		return "dst is empty"
	case len(grant.IP) == 0 && len(grant.App) == 0:
		return "ip is empty and no app capability is granted"
	default:
		return ""
	}
}

func wildcardFindings(locator string, sources, destinations []string, wildcard WildcardPolicy) []LintFinding {
	sourceStar := containsWildcard(sources)
	destinationStar := containsWildcard(destinations)
	switch wildcard {
	case WildcardOff:
		return nil
	case WildcardAnyToAny:
		if sourceStar && destinationStar {
			return []LintFinding{{
				ID:          LintOverbroadWildcard,
				Severity:    LintWarn,
				Rule:        locator,
				Value:       "src=*, dst=*",
				Evidence:    "grant lets any source reach any destination (src and dst are both *)",
				Remediation: "restrict the source or destination, or pass -wildcard off if this is intended",
				Trace: []string{
					locator + " source contains *",
					locator + " destination contains *",
					"any source may reach any destination",
				},
			}}
		}
	case WildcardAny:
		findings := make([]LintFinding, 0)
		if sourceStar {
			findings = append(findings, wildcardSideFinding(locator+fieldSrc))
		}
		if destinationStar {
			findings = append(findings, wildcardSideFinding(locator+fieldDst))
		}
		return findings
	}
	return nil
}

func wildcardSideFinding(locator string) LintFinding {
	return LintFinding{
		ID:          LintOverbroadWildcard,
		Severity:    LintWarn,
		Rule:        locator,
		Value:       "*",
		Evidence:    "selector is the unrestricted wildcard *",
		Remediation: "restrict the selector, or pass -wildcard any-to-any (the default) to allow standalone *",
		Trace:       []string{locator + " is *"},
	}
}

func sourceReferenceFindings(policy *tailscale.ACL, locator string, sources []string) []LintFinding {
	findings := make([]LintFinding, 0)
	for index, selector := range sources {
		rule := fmt.Sprintf("%s[%d]", locator, index)
		if finding, ok := sourceReferenceFinding(policy, rule, selector); ok {
			findings = append(findings, finding)
		}
	}
	return findings
}

func sourceReferenceFinding(policy *tailscale.ACL, rule, selector string) (LintFinding, bool) {
	selector = strings.TrimSpace(selector)
	if selector == "" || selector == "*" {
		return LintFinding{}, false
	}
	if reason := undefinedReferenceReason(selector, policy); reason != "" {
		return undefinedReferenceFinding(rule, selector, reason), true
	}
	return LintFinding{}, false
}

func destinationReferenceFindings(policy *tailscale.ACL, locator string, destinations []string) []LintFinding {
	findings := make([]LintFinding, 0)
	for index, destination := range destinations {
		host := destinationHost(destination)
		if host == "" || host == "*" {
			continue
		}
		rule := fmt.Sprintf("%s[%d]", locator, index)
		if finding, ok := destinationReferenceFinding(policy, rule, host); ok {
			findings = append(findings, finding)
		}
	}
	return findings
}

// nodeDestinationReferenceFindings validates portless grant dst, SSH dst, and
// recorder selectors. Unlike ACL network destinations, these selectors have no
// trailing port to strip.
func nodeDestinationReferenceFindings(
	policy *tailscale.ACL,
	locator string,
	destinations []string,
) []LintFinding {
	findings := make([]LintFinding, 0)
	for index, destination := range destinations {
		selector := strings.TrimSpace(destination)
		if selector == "" || selector == "*" {
			continue
		}
		rule := fmt.Sprintf("%s[%d]", locator, index)
		if finding, ok := destinationReferenceFinding(policy, rule, selector); ok {
			findings = append(findings, finding)
		}
	}
	return findings
}

func destinationReferenceFinding(
	policy *tailscale.ACL,
	rule string,
	selector string,
) (LintFinding, bool) {
	if strings.HasPrefix(selector, "tag:") {
		if _, ok := policy.TagOwners[selector]; !ok {
			return LintFinding{
				ID:          LintDstTagNoOwner,
				Severity:    LintError,
				Rule:        rule,
				Value:       selector,
				Evidence:    "destination tag " + selector + " has no entry in tagOwners, so no node can carry it",
				Remediation: "add a tagOwners entry for " + selector + ", or remove the destination",
				Trace: []string{
					rule + " destination tag " + selector,
					selector + " is not declared in tagOwners",
				},
			}, true
		}
		return LintFinding{}, false
	}
	if reason := undefinedReferenceReason(selector, policy); reason != "" {
		return undefinedReferenceFinding(rule, selector, reason), true
	}
	return LintFinding{}, false
}

func undefinedReferenceFinding(rule, value, reason string) LintFinding {
	return LintFinding{
		ID:          LintUndefinedReference,
		Severity:    LintError,
		Rule:        rule,
		Value:       value,
		Evidence:    value + " " + reason,
		Remediation: "define " + value + ", or correct the reference",
		Trace: []string{
			rule + " references " + value,
			value + " " + reason,
		},
	}
}

// undefinedReferenceReason reports why a selector names nothing the policy
// defines, or "" if it resolves. Autogroups are treated as defined by prefix
// alone: Tailscale extends the autogroup set over time, so flagging an unknown
// autogroup would false-positive the moment a new one ships.
func undefinedReferenceReason(selector string, policy *tailscale.ACL) string {
	switch {
	case selector == "" || selector == "*":
		return ""
	case strings.HasPrefix(selector, "autogroup:"):
		return ""
	case policycore.LooksLikeUser(selector):
		return ""
	case strings.HasPrefix(selector, "group:"):
		if _, ok := policy.Groups[selector]; !ok {
			return "is not defined in groups"
		}
		return ""
	case strings.HasPrefix(selector, "tag:"):
		if _, ok := policy.TagOwners[selector]; !ok {
			return "is not declared in tagOwners"
		}
		return ""
	case strings.HasPrefix(selector, "ipset:"):
		if _, ok := policy.IPSets[selector]; !ok {
			return "is not defined in ipsets"
		}
		return ""
	}
	if isLiteralAddress(selector) {
		return ""
	}
	if _, ok := policy.Hosts[selector]; ok {
		return ""
	}
	return "is not defined in hosts"
}

func lintDuplicateGrants(policy *tailscale.ACL) ([]LintFinding, error) {
	findings := make([]LintFinding, 0)
	firstSeen := make(map[string]int, len(policy.Grants))
	for index, grant := range policy.Grants {
		key, err := GrantSemanticKey(grant)
		if err != nil {
			return nil, err
		}
		if original, ok := firstSeen[key]; ok {
			locator := fmt.Sprintf("grants[%d]", index)
			findings = append(findings, LintFinding{
				ID:          LintDuplicateGrant,
				Severity:    LintWarn,
				Rule:        locator,
				Evidence:    fmt.Sprintf("grant %d is identical to grant %d", index, original),
				Remediation: "remove the duplicate grant",
				Trace: []string{
					fmt.Sprintf("%s canonicalizes to the same selectors as grants[%d]", locator, original),
				},
			})
			continue
		}
		firstSeen[key] = index
	}
	return findings, nil
}

func lintUnusedDefinitions(
	policy *tailscale.ACL,
	sshRules []tailscale.ACLSSH,
	sshTests []SSHTest,
) []LintFinding {
	referenced := collectReferences(policy, sshRules, sshTests)
	findings := make([]LintFinding, 0)
	add := func(id, kind, name, container string) {
		findings = append(findings, LintFinding{
			ID:          id,
			Severity:    LintInfo,
			Rule:        fmt.Sprintf("%s[%s]", container, name),
			Value:       name,
			Evidence:    fmt.Sprintf("%s %s is defined but no rule references it", kind, name),
			Remediation: "reference " + name + ", or remove the definition",
			Trace: []string{
				fmt.Sprintf("%s %s is defined in %s", kind, name, container),
				"no grant, acl, ssh, group, tagOwner, test, or sshTest references " + name,
			},
		})
	}
	for tag := range policy.TagOwners {
		if !referenced[tag] {
			add(LintUnusedTag, "tag", tag, "tagOwners")
		}
	}
	for group := range policy.Groups {
		if !referenced[group] {
			add(LintUnusedGroup, "group", group, "groups")
		}
	}
	for host := range policy.Hosts {
		if !referenced[host] {
			add(LintUnusedHost, "host", host, "hosts")
		}
	}
	for ipset := range policy.IPSets {
		if !referenced[ipset] {
			add(LintUnusedIPSet, "ipset", ipset, "ipsets")
		}
	}
	return findings
}

// collectReferences gathers every selector the policy uses anywhere. Network
// destination positions are normalized to their host (port stripped); SSH test
// destinations remain node selectors. A definition is unused when its name is
// absent from this set.
func collectReferences(
	policy *tailscale.ACL,
	sshRules []tailscale.ACLSSH,
	sshTests []SSHTest,
) map[string]bool {
	referenced := make(map[string]bool)
	for _, grant := range policy.Grants {
		addReferences(referenced, grant.Source)
		addReferences(referenced, grant.Destination)
	}
	for _, entry := range policy.ACLs {
		addReferences(referenced, aclSources(entry))
		addDestinationReferences(referenced, aclDestinations(entry))
	}
	for _, members := range policy.Groups {
		addReferences(referenced, members)
	}
	for _, owners := range policy.TagOwners {
		addReferences(referenced, owners)
	}
	addTestReferences(referenced, policy.Tests)
	addSSHRuleReferences(referenced, sshRules)
	addSSHTestReferences(referenced, sshTests)
	return referenced
}

func addReference(referenced map[string]bool, value string) {
	if value = strings.TrimSpace(value); value != "" {
		referenced[value] = true
	}
}

func addReferences(referenced map[string]bool, values []string) {
	for _, value := range values {
		addReference(referenced, value)
	}
}

func addDestinationReferences(referenced map[string]bool, destinations []string) {
	for _, destination := range destinations {
		addReference(referenced, destinationHost(destination))
	}
}

func addTestReferences(referenced map[string]bool, tests []tailscale.ACLTest) {
	for _, test := range tests {
		source := test.Source
		if source == "" {
			source = test.User
		}
		addReference(referenced, source)
		accept := test.Accept
		if len(accept) == 0 {
			accept = test.Allow
		}
		addDestinationReferences(referenced, accept)
		addDestinationReferences(referenced, test.Deny)
	}
}

func addSSHRuleReferences(referenced map[string]bool, rules []tailscale.ACLSSH) {
	for _, rule := range rules {
		addReferences(referenced, rule.Source)
		// Like SSH test destinations, an SSH rule's dst and recorder are node
		// selectors rather than network host:port targets, so a tag such as
		// tag:web must retain both colon-separated components. users is
		// deliberately absent: those are SSH login names, not policy
		// definitions.
		addReferences(referenced, rule.Destination)
		addReferences(referenced, rule.Recorder)
	}
}

func addSSHTestReferences(referenced map[string]bool, tests []SSHTest) {
	for _, test := range tests {
		addReference(referenced, test.Source)
		// SSH test destinations are node selectors, not network host:port
		// targets, so a tag such as tag:web must retain both colon-separated
		// components.
		addReferences(referenced, test.Destination)
	}
}

func aclSources(entry tailscale.ACLEntry) []string {
	if len(entry.Source) == 0 {
		return entry.Users
	}
	return entry.Source
}

func aclDestinations(entry tailscale.ACLEntry) []string {
	if len(entry.Destination) == 0 {
		return entry.Ports
	}
	return entry.Destination
}

// destinationHosts maps a destination selector list to just its host parts, used
// by the wildcard check so "*:443" counts as a "*" destination.
func destinationHosts(destinations []string) []string {
	hosts := make([]string, 0, len(destinations))
	for _, destination := range destinations {
		hosts = append(hosts, destinationHost(destination))
	}
	return hosts
}

// destinationHost strips a trailing :port from an ACL destination selector.
// Portless grant, SSH, and source selectors must not be passed here.
func destinationHost(destination string) string {
	if host, _, ok := splitSelectorPort(destination); ok {
		return host
	}
	return strings.TrimSpace(destination)
}

func containsWildcard(selectors []string) bool {
	for _, selector := range selectors {
		if strings.TrimSpace(selector) == "*" {
			return true
		}
	}
	return false
}

func isLiteralAddress(value string) bool {
	if _, err := netip.ParseAddr(strings.Trim(value, "[]")); err == nil {
		return true
	}
	_, err := netip.ParsePrefix(value)
	return err == nil
}
