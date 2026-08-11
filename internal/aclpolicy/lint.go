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

// LintSeverity ranks a lint finding. advice < info < warn < error.
type LintSeverity string

const (
	// LintAdvice is a heuristic worth considering, but not a defect. It ranks
	// below info so adding an advisory never changes existing lint exit codes.
	LintAdvice LintSeverity = "advice"
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
	LintBroadRuleUntested  = "broad-rule-untested"
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
	rankAdvice = iota
	rankInfo
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
	case LintAdvice:
		return rankAdvice
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
	case LintAdvice, LintInfo, LintWarn, LintError:
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
	Suggestion  string       `json:"suggestion,omitempty"`
	Trace       []string     `json:"trace,omitempty"`
}

// LintSummary contains aggregate finding counts by severity.
type LintSummary struct {
	Total int `json:"total"`
	Error int `json:"error"`
	Warn  int `json:"warn"`
	Info  int `json:"info"`
	// Advice is omitted when zero so reports with no advisories retain their
	// existing JSON shape byte for byte.
	Advice int `json:"advice,omitempty"`
	// SCIMGroupRefs counts distinct SCIM/IdP-synced group selectors
	// (group:<name>@<domain>) that were exempted from undefined-reference
	// reporting because they resolve at the control plane rather than in the
	// local groups map. It is omitted when zero so a policy with no such
	// references retains its existing JSON shape byte for byte, the same
	// convention as Advice above.
	SCIMGroupRefs int `json:"scim_group_refs,omitempty"`
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
	// AllowBroadDestinations excludes destination selectors that are
	// intentionally reachable from a blanket source on every port.
	AllowBroadDestinations []string
	// StrictSCIMGroups restores the pre-exemption behavior: any group:<name>
	// not present in the local groups map is an undefined-reference error, even
	// when it is SCIM-shaped (group:<name>@<domain>). Off by default so
	// IdP/SCIM-synced groups, which resolve at the control plane, are not
	// false-positived by the static linter.
	StrictSCIMGroups bool
	// SCIMDomains narrows the SCIM-group exemption to selectors whose @domain
	// suffix is listed (ASCII-case-insensitive). Empty means any group:*@*
	// selector is treated as SCIM-shaped. Ignored when StrictSCIMGroups is set.
	SCIMDomains []string
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
		{
			LintUndefinedReference,
			LintError,
			"a src/dst names an undefined selector, or a route/exit-node auto-approver is unsupported or undefined",
		},
		{LintDstTagNoOwner, LintError, "a destination tag has no tagOwners entry, so no node can carry it"},
		{LintOverbroadWildcard, LintWarn, "an over-broad * selector (tuned by -wildcard)"},
		{
			LintBroadRuleUntested,
			LintAdvice,
			"a broad all-port grant reaches a concrete destination that no deny assertion names",
		},
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

	linter := &refLinter{
		policy:   policy,
		scim:     scimConfig{strict: opts.StrictSCIMGroups, domains: opts.SCIMDomains},
		scimRefs: make(map[string]bool),
	}

	findings := make([]LintFinding, 0)
	findings = append(findings, linter.lintGrants(wildcard)...)
	findings = append(findings, lintBroadRuleUntested(policy, opts.AllowBroadDestinations)...)
	findings = append(findings, linter.lintACLs(wildcard)...)
	findings = append(findings, linter.lintSSHRules(sshRules)...)
	findings = append(findings, linter.lintSSHTests(sshTests)...)
	findings = append(findings, linter.lintAutoApprovers()...)
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
	report.Summary.SCIMGroupRefs = len(linter.scimRefs)
	for _, finding := range findings {
		report.Summary.Total++
		switch finding.Severity {
		case LintAdvice:
			report.Summary.Advice++
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

// scimConfig captures how the linter treats SCIM/IdP-synced group selectors.
// It is threaded through the reference-finding chain (rather than held in a
// global) so the classifiers stay pure and testable.
type scimConfig struct {
	strict  bool
	domains []string
}

// refLinter carries the state the reference-finding walk needs: the policy it
// resolves selectors against, the SCIM-group configuration, and an accumulator
// of the distinct SCIM-shaped selectors that were exempted so the summary can
// report their count.
type refLinter struct {
	policy   *tailscale.ACL
	scim     scimConfig
	scimRefs map[string]bool
}

func (l *refLinter) lintGrants(wildcard WildcardPolicy) []LintFinding {
	policy := l.policy
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
		findings = append(findings, l.sourceReferenceFindings(locator+fieldSrc, grant.Source)...)
		findings = append(findings, l.nodeDestinationReferenceFindings(locator+fieldDst, grant.Destination)...)
	}
	return findings
}

func (l *refLinter) lintACLs(wildcard WildcardPolicy) []LintFinding {
	policy := l.policy
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
		findings = append(findings, l.sourceReferenceFindings(locator+sourceField, sources)...)
		findings = append(findings, l.destinationReferenceFindings(locator+destinationField, destinations)...)
	}
	return findings
}

func (l *refLinter) lintSSHRules(rules []tailscale.ACLSSH) []LintFinding {
	findings := make([]LintFinding, 0)
	for index, rule := range rules {
		locator := fmt.Sprintf("ssh[%d]", index)
		findings = append(findings,
			l.sourceReferenceFindings(locator+fieldSrc, rule.Source)...)
		findings = append(findings,
			l.nodeDestinationReferenceFindings(locator+fieldDst, rule.Destination)...)
		// Recorder entries are node selectors, just like SSH destinations.
		findings = append(findings,
			l.nodeDestinationReferenceFindings(locator+".recorder", rule.Recorder)...)
	}
	return findings
}

func (l *refLinter) lintSSHTests(tests []SSHTest) []LintFinding {
	findings := make([]LintFinding, 0)
	for index, test := range tests {
		locator := fmt.Sprintf("sshTests[%d]", index)
		if finding, ok := l.sourceReferenceFinding(locator+fieldSrc, test.Source); ok {
			findings = append(findings, finding)
		}
		findings = append(findings,
			l.nodeDestinationReferenceFindings(locator+fieldDst, test.Destination)...)
	}
	return findings
}

// lintAutoApprovers validates the narrower selector vocabulary Tailscale
// permits in autoApprovers.routes and autoApprovers.exitNode, then checks legal
// group and tag selectors as references. The route keys are CIDRs, not
// references, and are not checked here. services has no authoring command and
// is retained as the source-style reference walk the pinned client exposes.
func (l *refLinter) lintAutoApprovers() []LintFinding {
	policy := l.policy
	findings := make([]LintFinding, 0)
	autoApprovers := policy.AutoApprovers
	if autoApprovers == nil {
		return findings
	}
	for route, approvers := range autoApprovers.Routes {
		findings = append(findings, l.autoApproverReferenceFindings(
			fmt.Sprintf("autoApprovers.routes[%s]", route), approvers)...)
	}
	findings = append(findings, l.autoApproverReferenceFindings(
		"autoApprovers.exitNode", autoApprovers.ExitNode)...)
	for service, approvers := range autoApprovers.Services {
		findings = append(findings, l.sourceReferenceFindings(
			fmt.Sprintf("autoApprovers.services[%s]", service), approvers)...)
	}
	return findings
}

func (l *refLinter) autoApproverReferenceFindings(
	locator string,
	approvers []string,
) []LintFinding {
	findings := make([]LintFinding, 0)
	for index, approver := range approvers {
		approver = strings.TrimSpace(approver)
		rule := fmt.Sprintf("%s[%d]", locator, index)
		if !isAutoApproverSelector(approver) {
			findings = append(findings, invalidAutoApproverSelectorFinding(rule, approver))
			continue
		}
		if reason := l.undefinedReferenceReason(approver); reason != "" {
			findings = append(findings, undefinedReferenceFinding(rule, approver, reason))
		}
	}
	return findings
}

func invalidAutoApproverSelectorFinding(rule, selector string) LintFinding {
	return LintFinding{
		ID:       LintUndefinedReference,
		Severity: LintError,
		Rule:     rule,
		Value:    selector,
		Evidence: fmt.Sprintf(
			"auto-approver selector %q is not a login email, group:, autogroup:, or tag: selector",
			selector),
		Remediation: "replace it with a login email, group:, autogroup:, or tag: selector",
		Trace: []string{
			fmt.Sprintf("%s uses %q as an auto-approver", rule, selector),
			"route and exit-node auto-approvers allow only login emails, groups, autogroups, and tags",
		},
	}
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
	if wildcard == WildcardOff {
		return nil
	}
	findings := make([]LintFinding, 0)

	// autogroup:danger-all is deliberately not tuned by -wildcard. That policy
	// exists because a standalone "*" is idiomatic and common; danger-all is an
	// explicit escape hatch that names every device including ones outside the
	// tailnet, so it is reported on either side whenever the check is enabled.
	if containsDangerAll(sources) {
		findings = append(findings, dangerAllSideFinding(locator+fieldSrc))
	}
	if containsDangerAll(destinations) {
		findings = append(findings, dangerAllSideFinding(locator+fieldDst))
	}

	sourceStar := containsWildcard(sources)
	destinationStar := containsWildcard(destinations)
	switch wildcard {
	case WildcardOff:
		// Unreachable — the early return above handles it. Kept so exhaustive
		// keeps this switch honest if that early return is ever removed.
		return nil
	case WildcardAnyToAny:
		if sourceStar && destinationStar {
			findings = append(findings, LintFinding{
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
			})
		}
	case WildcardAny:
		if sourceStar {
			findings = append(findings, wildcardSideFinding(locator+fieldSrc))
		}
		if destinationStar {
			findings = append(findings, wildcardSideFinding(locator+fieldDst))
		}
	}
	return findings
}

func containsDangerAll(selectors []string) bool {
	for _, selector := range selectors {
		if strings.TrimSpace(selector) == autogroupDangerAll {
			return true
		}
	}
	return false
}

func dangerAllSideFinding(locator string) LintFinding {
	return LintFinding{
		ID:       LintOverbroadWildcard,
		Severity: LintWarn,
		Rule:     locator,
		Value:    autogroupDangerAll,
		Evidence: "selector " + autogroupDangerAll +
			" names every device, including devices outside the tailnet",
		Remediation: "replace " + autogroupDangerAll +
			" with the specific users, groups, or tags the rule is for",
		Trace: []string{locator + " is " + autogroupDangerAll},
	}
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

func (l *refLinter) sourceReferenceFindings(locator string, sources []string) []LintFinding {
	findings := make([]LintFinding, 0)
	for index, selector := range sources {
		rule := fmt.Sprintf("%s[%d]", locator, index)
		if finding, ok := l.sourceReferenceFinding(rule, selector); ok {
			findings = append(findings, finding)
		}
	}
	return findings
}

func (l *refLinter) sourceReferenceFinding(rule, selector string) (LintFinding, bool) {
	selector = strings.TrimSpace(selector)
	if selector == "" || selector == "*" {
		return LintFinding{}, false
	}
	if reason := l.undefinedReferenceReason(selector); reason != "" {
		return undefinedReferenceFinding(rule, selector, reason), true
	}
	return LintFinding{}, false
}

func (l *refLinter) destinationReferenceFindings(locator string, destinations []string) []LintFinding {
	findings := make([]LintFinding, 0)
	for index, destination := range destinations {
		host := destinationHost(destination)
		if host == "" || host == "*" {
			continue
		}
		rule := fmt.Sprintf("%s[%d]", locator, index)
		if finding, ok := l.destinationReferenceFinding(rule, host); ok {
			findings = append(findings, finding)
		}
	}
	return findings
}

// nodeDestinationReferenceFindings validates portless grant dst, SSH dst, and
// recorder selectors. Unlike ACL network destinations, these selectors have no
// trailing port to strip.
func (l *refLinter) nodeDestinationReferenceFindings(
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
		if finding, ok := l.destinationReferenceFinding(rule, selector); ok {
			findings = append(findings, finding)
		}
	}
	return findings
}

func (l *refLinter) destinationReferenceFinding(
	rule string,
	selector string,
) (LintFinding, bool) {
	policy := l.policy
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
	if reason := l.undefinedReferenceReason(selector); reason != "" {
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
func (l *refLinter) undefinedReferenceReason(selector string) string {
	policy := l.policy
	switch {
	case selector == "" || selector == "*":
		return ""
	case strings.HasPrefix(selector, "autogroup:"):
		return ""
	case policycore.LooksLikeUser(selector):
		return ""
	case strings.HasPrefix(selector, "group:"):
		if _, ok := policy.Groups[selector]; ok {
			return ""
		}
		// A group absent from the local map still resolves at the control plane
		// when it is IdP/SCIM-synced (group:<name>@<domain>). Unless strict mode
		// is requested, treat a SCIM-shaped selector as resolved and count it,
		// so the static linter does not false-positive every synced group.
		if !l.scim.strict && policycore.LooksLikeSCIMGroup(selector, l.scim.domains) {
			l.scimRefs[selector] = true
			return ""
		}
		return "is not defined in groups"
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
				"no grant, acl, ssh, group, tagOwner, autoApprovers, test, or sshTest references " + name,
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
	// A legal approver references its group or tag exactly the way a grant
	// source does, so a definition named only by autoApprovers is used, not
	// unused. Illegal host and ipset selectors do not count as references merely
	// because a hand-authored policy placed them in an approver list.
	if autoApprovers := policy.AutoApprovers; autoApprovers != nil {
		for _, approvers := range autoApprovers.Routes {
			addAutoApproverReferences(referenced, approvers)
		}
		addAutoApproverReferences(referenced, autoApprovers.ExitNode)
		for _, approvers := range autoApprovers.Services {
			addReferences(referenced, approvers)
		}
	}
	addTestReferences(referenced, policy.Tests)
	addSSHRuleReferences(referenced, sshRules)
	addSSHTestReferences(referenced, sshTests)
	return referenced
}

func addAutoApproverReferences(referenced map[string]bool, approvers []string) {
	for _, approver := range approvers {
		approver = strings.TrimSpace(approver)
		if isAutoApproverSelector(approver) {
			addReference(referenced, approver)
		}
	}
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
	return policycore.ContainsLiteralWildcard(selectors)
}

func isLiteralAddress(value string) bool {
	if _, err := netip.ParseAddr(strings.Trim(value, "[]")); err == nil {
		return true
	}
	_, err := netip.ParsePrefix(value)
	return err == nil
}
