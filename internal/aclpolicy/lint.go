package aclpolicy

import (
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"unicode/utf8"

	tailscale "tailscale.com/client/tailscale/v2"

	"github.com/rshade/tailscale-utils/policycore"
	"github.com/rshade/tailscale-utils/policycore/posture"
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
	LintUndefinedReference    = "undefined-reference"
	LintDstTagNoOwner         = "dst-tag-no-owner"
	LintOverbroadWildcard     = "overbroad-wildcard"
	LintBroadRuleUntested     = "broad-rule-untested"
	LintGrantEmpty            = "grant-empty"
	LintDuplicateGrant        = "duplicate-grant"
	LintIPSetMixedOperations  = "ipset-mixed-operations"
	LintUnusedTag             = "unused-tag"
	LintUnusedGroup           = "unused-group"
	LintUnusedHost            = "unused-host"
	LintUnusedIPSet           = "unused-ipset"
	LintUnusedPosture         = "unused-posture"
	LintPostureInvalid        = "posture-invalid"
	LintServiceInSource       = "svc-in-source"
	LintServiceInSSH          = "svc-in-ssh"
	LintServiceUnknown        = "svc-unknown"
	LintSCIMGroupShadowsLocal = "scim-group-shadows-local"
	LintSCIMGroupUnknown      = "scim-group-unsynced"
)

// scimNotSyncingMarker is the stable substring of the control-plane validation
// warning emitted when a policy references a group that is not actually syncing
// from SCIM. The full sentence ("... and will be ignored by rules in the policy
// file") is matched only on this fragment so a trailing-word tweak upstream does
// not silence the check.
const scimNotSyncingMarker = "is not syncing from scim"

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
	fieldSrc        = ".src"
	fieldUsers      = ".users"
	fieldDst        = ".dst"
	fieldPorts      = ".ports"
	fieldSrcPosture = ".srcPosture"
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
	// SvcRefs counts distinct svc: (Tailscale Service) selectors that were
	// exempted from undefined-reference reporting because they resolve at the
	// control plane (the vip-services API) rather than in the local policy. It
	// is omitted when zero so a policy with no service references retains its
	// existing JSON shape byte for byte, the same convention as Advice and
	// SCIMGroupRefs above.
	SvcRefs int `json:"svc_refs,omitempty"`
	// SvcDstRefs counts the distinct svc: selectors in traffic destinations
	// that --online-validation can check. It excludes illegal positions such as
	// rule sources and SSH node selectors even though SvcRefs still counts those
	// references. It is omitted when zero for compatibility with older reports.
	SvcDstRefs int `json:"svc_dst_refs,omitempty"`
}

// ServiceRef is one distinct service selector eligible for online existence
// validation. Rule is the locator of its first occurrence in the policy.
type ServiceRef struct {
	Selector string
	Rule     string
}

// LintReport is the pure, deterministic result of statically linting a policy.
type LintReport struct {
	Findings []LintFinding `json:"findings"`
	Summary  LintSummary   `json:"summary"`
}

// CountAtLeast reports how many findings are at least as severe as threshold.
func (r *LintReport) CountAtLeast(threshold LintSeverity) int {
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
			"a selector is undefined or invalid in its policy position",
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
		{
			LintIPSetMixedOperations,
			LintError,
			"an ipset mixes a remove operation with a member that has no add/remove operation",
		},
		{LintUnusedTag, LintInfo, "a tag is defined but referenced by no rule"},
		{LintUnusedGroup, LintInfo, "a group is defined but referenced by no rule"},
		{LintUnusedHost, LintInfo, "a host alias is defined but referenced by no rule"},
		{LintUnusedIPSet, LintInfo, "an ipset is defined but referenced by no rule"},
		{LintUnusedPosture, LintInfo, "a posture is defined but no srcPosture or defaultSrcPosture references it"},
		{
			LintPostureInvalid,
			LintError,
			"a posture expression is unparseable or names an out-of-vocabulary value (unknown attributes warn)",
		},
		{
			LintServiceInSource,
			LintWarn,
			"a svc: service selector used as a rule source; Tailscale services are destination-only",
		},
		{
			LintServiceInSSH,
			LintError,
			"a svc: service selector used as an SSH destination or recorder; those fields require node selectors",
		},
		{
			LintServiceUnknown,
			LintWarn,
			"a svc: destination names a service not found in the tailnet (requires --online-validation)",
		},
		{
			LintSCIMGroupShadowsLocal,
			LintWarn,
			"a SCIM-shaped group reference has the same name half as a declared local group",
		},
		{
			LintSCIMGroupUnknown,
			LintWarn,
			"a group: reference the control plane reports is not syncing from SCIM (requires --online-validation)",
		},
	}
}

// EvaluateLint statically checks a policy for hygiene problems derivable from
// the policy alone — no control-plane access. It reports dead grants, undefined
// tag/group/host/ipset/posture references, destination tags with no owner,
// over-broad wildcards, duplicate grants, and definitions referenced by nothing.
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

// EvaluateServiceExistence is the pure, network-free classifier behind lint
// --online-validation. exists contains one explicit control-plane answer per
// selector that was successfully looked up: true means it exists and false
// means the API answered not found. A selector absent from the map was not
// checked and stays silent; collection failures are handled by the caller.
//
// A missing service is a warn, not an error, because Tailscale services are
// late-bound — the control plane itself validates a policy that names one that
// does not yet exist.
func EvaluateServiceExistence(refs []ServiceRef, exists map[string]bool) []LintFinding {
	findings := make([]LintFinding, 0)
	seen := make(map[string]bool)
	for _, ref := range refs {
		selector := strings.TrimSpace(ref.Selector)
		found, checked := exists[selector]
		if !looksLikeService(selector) || !checked || found || seen[selector] {
			continue
		}
		seen[selector] = true
		findings = append(findings, LintFinding{
			ID:          LintServiceUnknown,
			Severity:    LintWarn,
			Rule:        ref.Rule,
			Value:       selector,
			Evidence:    selector + " is not a service defined in the tailnet",
			Remediation: "create the service, or correct the reference; services are late-bound, so this is advisory",
			Trace: []string{
				ref.Rule + " references " + selector,
				"the vip-services lookup for " + selector + " returned not found",
			},
		})
	}
	return findings
}

// ServiceDestinationRefs returns the distinct service selectors in policy
// positions where Tailscale permits a service as a traffic destination. Each
// ref carries its first locator. Sources, SSH node selectors, recorders, and
// auto-approver identities are intentionally excluded: those are hard misuse,
// not candidates for a late-bound existence check.
func ServiceDestinationRefs(policy *tailscale.ACL) []ServiceRef {
	if policy == nil {
		return nil
	}
	refs := make([]ServiceRef, 0)
	seen := make(map[string]bool)
	add := func(rule, selector string) {
		selector = strings.TrimSpace(selector)
		if !looksLikeService(selector) || seen[selector] {
			return
		}
		seen[selector] = true
		refs = append(refs, ServiceRef{Selector: selector, Rule: rule})
	}
	for index, grant := range policy.Grants {
		for position, destination := range grant.Destination {
			add(fmt.Sprintf("grants[%d].dst[%d]", index, position), destination)
		}
	}
	for index, entry := range policy.ACLs {
		field := fieldDst
		if len(entry.Destination) == 0 {
			field = fieldPorts
		}
		for position, destination := range aclDestinations(entry) {
			add(fmt.Sprintf("acls[%d]%s[%d]", index, field, position), destinationHost(destination))
		}
	}
	for index, test := range policy.Tests {
		accept := test.Accept
		if len(accept) == 0 {
			accept = test.Allow
		}
		for position, destination := range accept {
			add(fmt.Sprintf("tests[%d].accept[%d]", index, position), destinationHost(destination))
		}
		for position, destination := range test.Deny {
			add(fmt.Sprintf("tests[%d].deny[%d]", index, position), destinationHost(destination))
		}
	}
	return refs
}

// EvaluateSCIMGroupSync is the pure, network-free classifier behind the SCIM
// half of lint --online-validation. Because the control plane exposes no API to
// list IdP/SCIM-synced groups, sync status is discovered indirectly: the policy
// is submitted to /acl/validate, and a group referenced but not actually syncing
// comes back as a validation warning. The caller flattens those warning strings
// (ValidationResult.Warnings[].Warnings) and passes them here, keeping this
// classifier unit-testable with no network.
//
// For each warning that reports a group is not syncing from SCIM it emits one
// LintWarn scim-group-unsynced finding. It is a warn, not an error, because the
// policy still validates — the not-syncing rule is simply ignored — so this is
// advisory, mirroring svc-unknown. Findings are deduplicated by the offending
// group: selector (or by the whole warning text when no selector can be
// extracted). This is independent of the offline scim_group_refs count: offline
// counts SCIM-shaped references it exempted, online reports which of them the
// control plane says are not actually syncing.
func EvaluateSCIMGroupSync(warnings []string) []LintFinding {
	findings := make([]LintFinding, 0)
	seen := make(map[string]bool)
	for _, warning := range warnings {
		if !strings.Contains(strings.ToLower(warning), scimNotSyncingMarker) {
			continue
		}
		selector := extractGroupSelector(warning)
		key := selector
		if key == "" {
			key = warning
		}
		if seen[key] {
			continue
		}
		seen[key] = true
		findings = append(findings, LintFinding{
			ID:          LintSCIMGroupUnknown,
			Severity:    LintWarn,
			Rule:        "scim",
			Value:       selector,
			Evidence:    warning,
			Remediation: "ensure the group is provisioned and syncing in your IdP/SCIM, or remove the reference",
			Trace:       []string{"control plane reported: " + warning},
		})
	}
	return findings
}

// extractGroupSelector returns the first group: token in a control-plane warning
// (from "group:" to the next whitespace or quote), or "" when the warning names
// no selector. The control plane phrases the warning around the offending
// selector but the surrounding words are not a stable contract, so only the
// group: token is lifted out.
func extractGroupSelector(warning string) string {
	start := strings.Index(warning, "group:")
	if start < 0 {
		return ""
	}
	rest := warning[start:]
	end := strings.IndexFunc(rest, func(r rune) bool {
		return r == ' ' || r == '\t' || r == '\n' || r == '"' || r == '\'' || r == '`'
	})
	if end < 0 {
		return rest
	}
	return rest[:end]
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
		svcRefs:  make(map[string]bool),
	}

	findings := make([]LintFinding, 0)
	findings = append(findings, linter.lintGrants(wildcard)...)
	findings = append(findings, lintBroadRuleUntested(policy, opts.AllowBroadDestinations)...)
	findings = append(findings, linter.lintACLs(wildcard)...)
	findings = append(findings,
		linter.postureReferenceFindings("defaultSrcPosture", policy.DefaultSourcePosture)...)
	linter.countTestServiceReferences(policy.Tests)
	findings = append(findings, linter.lintSSHRules(sshRules)...)
	findings = append(findings, linter.lintSSHTests(sshTests)...)
	findings = append(findings, linter.lintAutoApprovers()...)
	findings = append(findings, linter.sideFindings...)
	duplicates, err := lintDuplicateGrants(policy)
	if err != nil {
		return LintReport{}, err
	}
	findings = append(findings, duplicates...)
	findings = append(findings, lintIPSetOperations(policy)...)
	findings = append(findings, lintUnusedDefinitions(policy, sshRules, sshTests)...)
	findings = append(findings, lintPostureExpressions(policy)...)

	report := LintReport{}
	report.Summary.SCIMGroupRefs = len(linter.scimRefs)
	report.Summary.SvcRefs = len(linter.svcRefs)
	report.Summary.SvcDstRefs = len(ServiceDestinationRefs(policy))
	report.Add(findings...)
	return report, nil
}

// Add appends findings, updates the severity counters, and restores the stable
// order. It exists so a caller that discovers findings after the offline pass -
// lint's --online-validation is the only one today - cannot drift from the
// counting and ordering this package already does. Duplicating that switch
// outside aclpolicy meant a newly added severity would silently produce a
// Summary whose buckets no longer sum to Total, with no compile error and no
// failing test to catch it.
func (r *LintReport) Add(findings ...LintFinding) {
	r.Findings = append(r.Findings, findings...)
	for _, finding := range findings {
		r.Summary.Total++
		switch finding.Severity {
		case LintAdvice:
			r.Summary.Advice++
		case LintError:
			r.Summary.Error++
		case LintWarn:
			r.Summary.Warn++
		case LintInfo:
			r.Summary.Info++
		}
	}
	// Sorted on every Add rather than once at the end of the offline pass, so
	// findings appended later stay interleaved by locator instead of trailing
	// the sorted block. The unused-definition checks iterate over maps, so this
	// is what makes the output deterministic at all.
	sort.SliceStable(r.Findings, func(i, j int) bool {
		if r.Findings[i].Rule != r.Findings[j].Rule {
			return r.Findings[i].Rule < r.Findings[j].Rule
		}
		if r.Findings[i].ID != r.Findings[j].ID {
			return r.Findings[i].ID < r.Findings[j].ID
		}
		return r.Findings[i].Value < r.Findings[j].Value
	})
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
	// sideFindings carries extra findings discovered while resolving a selector.
	// A SCIM/local collision can coexist with either the configured exemption or
	// an undefined-reference when a domain filter excludes the selector.
	sideFindings []LintFinding
	// svcRefs accumulates the distinct svc: selectors seen in any position, so
	// the summary can report their count. Services resolve at the control plane,
	// so a static run only counts them; --online-validation checks existence.
	svcRefs map[string]bool
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
		findings = append(findings, l.postureReferenceFindings(locator+fieldSrcPosture, grant.SrcPosture)...)
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
		findings = append(findings, l.postureReferenceFindings(locator+fieldSrcPosture, entry.SourcePosture)...)
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
			l.sshNodeReferenceFindings(locator+fieldDst, rule.Destination)...)
		// Recorder entries are node selectors, just like SSH destinations.
		findings = append(findings,
			l.sshNodeReferenceFindings(locator+".recorder", rule.Recorder)...)
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
			l.sshNodeReferenceFindings(locator+fieldDst, test.Destination)...)
	}
	return findings
}

// countTestServiceReferences covers policy test assertions, which are legal
// traffic destinations but are not part of the rule-reference lint walk. The
// accept and allow fields are aliases; malformed input that sets both is
// rejected by the test evaluator, so the effective field follows that same
// normalization here.
func (l *refLinter) countTestServiceReferences(tests []tailscale.ACLTest) {
	for _, test := range tests {
		accept := test.Accept
		if len(accept) == 0 {
			accept = test.Allow
		}
		for _, destination := range accept {
			l.countServiceReference(destinationHost(destination))
		}
		for _, destination := range test.Deny {
			l.countServiceReference(destinationHost(destination))
		}
	}
}

func (l *refLinter) countServiceReference(selector string) bool {
	selector = strings.TrimSpace(selector)
	if !looksLikeService(selector) {
		return false
	}
	l.svcRefs[selector] = true
	return true
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
		if reason := l.undefinedReferenceReason(rule, approver); reason != "" {
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
	// A svc: selector on the source side is destination-only: the control plane
	// rejects it outright ("svc:... not valid on the src side of a rule"). Lint
	// stays advisory — plan/validate give the authoritative rejection — so this
	// is a warn, not an error, and it must not also route through
	// undefinedReferenceReason (which the svc: case there exempts anyway) and
	// double-report. Count it so svc_refs is position-independent.
	if l.countServiceReference(selector) {
		return serviceInSourceFinding(rule, selector), true
	}
	if reason := l.undefinedReferenceReason(rule, selector); reason != "" {
		return undefinedReferenceFinding(rule, selector, reason), true
	}
	return LintFinding{}, false
}

// sshNodeReferenceFindings validates SSH destinations and recorders without
// routing services through the generic destination exemption. Those fields
// accept node selectors, not service traffic destinations, so svc: is a hard
// misuse and must never become an online lookup candidate.
func (l *refLinter) sshNodeReferenceFindings(
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
		if l.countServiceReference(selector) {
			findings = append(findings, serviceInSSHFinding(rule, selector))
			continue
		}
		if finding, ok := l.destinationReferenceFinding(rule, selector); ok {
			findings = append(findings, finding)
		}
	}
	return findings
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
	if reason := l.undefinedReferenceReason(rule, selector); reason != "" {
		return undefinedReferenceFinding(rule, selector, reason), true
	}
	return LintFinding{}, false
}

// postureReferenceFindings validates srcPosture and defaultSrcPosture entries
// against the policy's postures map. Names resolve with NormalizePostureName,
// the function posture set and posture remove already share, so lint and
// authoring agree on what a name refers to.
func (l *refLinter) postureReferenceFindings(locator string, postures []string) []LintFinding {
	findings := make([]LintFinding, 0)
	for index, name := range postures {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		rule := fmt.Sprintf("%s[%d]", locator, index)
		normalized, err := NormalizePostureName(name)
		if err != nil {
			findings = append(findings, undefinedReferenceFinding(rule, name, err.Error()))
			continue
		}
		if _, ok := l.policy.Postures[normalized]; !ok {
			findings = append(findings,
				undefinedReferenceFinding(rule, normalized, "is not defined in postures"))
		}
	}
	return findings
}

func serviceInSourceFinding(rule, selector string) LintFinding {
	return LintFinding{
		ID:          LintServiceInSource,
		Severity:    LintWarn,
		Rule:        rule,
		Value:       selector,
		Evidence:    selector + " used as a source; Tailscale services are destination-only",
		Remediation: "move " + selector + " to dst, or correct the reference",
		Trace: []string{
			rule + " references " + selector,
			selector + " is a Tailscale service, which is valid only on the destination side of a rule",
		},
	}
}

func serviceInSSHFinding(rule, selector string) LintFinding {
	return LintFinding{
		ID:          LintServiceInSSH,
		Severity:    LintError,
		Rule:        rule,
		Value:       selector,
		Evidence:    selector + " used as an SSH node selector; services are traffic destinations, not nodes",
		Remediation: "replace " + selector + " with a node selector such as a user, group, tag, host, or autogroup",
		Trace: []string{
			rule + " references " + selector,
			"SSH destinations and recorders require node selectors; svc: names a Tailscale Service",
		},
	}
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
func (l *refLinter) undefinedReferenceReason(rule, selector string) string {
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
		// No pinned Tailscale dependency exposes the control plane's group-name
		// validator, so an @-bearing local key cannot be ruled out with a Tier-2
		// provenance guard. Detect the ambiguity from the policy in hand instead:
		// if the pre-@ name is declared locally, surface that collision whether or
		// not the configured domain filter exempts the full selector. Strict mode
		// disables the exemption entirely and retains its existing single hard
		// undefined-reference finding.
		if !l.scim.strict && looksLikeSCIMGroup(selector, nil) {
			localGroup := scimLocalGroupName(selector)
			if _, ok := policy.Groups[localGroup]; ok {
				l.sideFindings = append(l.sideFindings,
					scimGroupShadowsLocalFinding(rule, selector, localGroup))
			}
		}
		// A group absent from the local map still resolves at the control plane
		// when it is IdP/SCIM-synced (group:<name>@<domain>). Unless strict mode
		// is requested, treat a SCIM-shaped selector as resolved and count it,
		// so the static linter does not false-positive every synced group.
		if !l.scim.strict && looksLikeSCIMGroup(selector, l.scim.domains) {
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
	case looksLikeService(selector):
		// A svc: selector names a Tailscale Service, which resolves at the
		// control plane (the vip-services API) and never in the policy file, so
		// it is never an undefined-host reference. Count it and exempt it in
		// legal traffic-destination positions; callers reject illegal positions
		// before reaching this exemption. --online-validation checks only the
		// legal destination subset.
		l.countServiceReference(selector)
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

func scimGroupShadowsLocalFinding(rule, selector, localGroup string) LintFinding {
	return LintFinding{
		ID:       LintSCIMGroupShadowsLocal,
		Severity: LintWarn,
		Rule:     rule,
		Value:    selector,
		Evidence: selector + " has a SCIM-shaped name whose local name half " +
			localGroup + " is also declared in groups",
		Remediation: "verify " + selector + " is a synced SCIM group; otherwise replace it with " +
			localGroup + " or rename one of the groups; use -scim-domains or -strict-scim-groups to constrain the exemption",
		Trace: []string{
			rule + " references " + selector,
			"the policy also declares local group " + localGroup,
			"the static linter cannot prove whether " + selector + " exists at the control plane",
		},
	}
}

// looksLikeService reports whether selector names a Tailscale Service
// (svc:<name>). Services resolve at the control plane (the vip-services API),
// never in a policy's local definitions, so like autogroups the name is
// recognized by its prefix alone; a static linter has nothing local to resolve
// the remainder against. This is a lint-hygiene heuristic (whether to suppress
// an undefined-reference finding), not selector resolution, so it lives here
// rather than in policycore.
// The name must be non-empty, for the same reason looksLikeSCIMGroup requires
// both halves: recognizing a selector suppresses undefined-reference, so a bare
// "svc:" would be declared resolvable while naming nothing. A policy rendered
// from "svc:${SERVICE_NAME}" with the variable unset produces exactly that.
func looksLikeService(selector string) bool {
	return len(selector) > len("svc:") && strings.HasPrefix(selector, "svc:")
}

// looksLikeSCIMGroup reports whether selector names an IdP/SCIM-synced group
// (group:<name>@<domain>). With no domains, any group:*@* matches; with
// domains, a selector matches when its @domain equals a listed domain or is a
// subdomain of one (ASCII-case-insensitive) — so example.com also covers
// eng.example.com. The group name portion may contain spaces (e.g.
// group:finance team@example.com); only the substring after the last "@" is
// treated as the domain.
//
// It is a name-shape heuristic, not a membership or legality check: no pinned
// dependency exposes a group-name validator, and the control plane is the
// authority. An @-bearing selector can therefore collide with a local group;
// undefinedReferenceReason detects that policy-local invariant and emits
// scim-group-shadows-local. Domain narrowing and strict mode cover collisions
// the local policy cannot reveal. There is no upstream symbol against which a
// Tier-2 build guard could be written, so the tailscale.com test-only dependency
// must not be widened chasing one. Like looksLikeService, this is a lint-hygiene
// heuristic and stays outside policycore's selector-resolution surface.
func looksLikeSCIMGroup(selector string, domains []string) bool {
	remainder, ok := strings.CutPrefix(selector, "group:")
	if !ok {
		return false
	}
	// Both halves must be non-empty. The exemption suppresses an
	// undefined-reference error, so a selector that is merely "@-shaped" rather
	// than SCIM-shaped must not qualify: a templated policy that emits
	// "group:${TEAM}@${DOMAIN}" with one variable unset produces "group:eng@"
	// or "group:@corp.com", and both are hard undefined references.
	at := strings.LastIndex(remainder, "@")
	if at <= 0 || at == len(remainder)-1 {
		return false
	}
	if len(domains) == 0 {
		return true
	}
	domain := remainder[at+1:]
	for _, candidate := range domains {
		if domainMatches(domain, candidate) {
			return true
		}
	}
	return false
}

// scimLocalGroupName returns the local key whose name portion precedes the last
// @ in a selector looksLikeSCIMGroup has already accepted. SCIM names may
// contain spaces and earlier @ characters, so the split must match that
// heuristic exactly rather than applying an email-address parser.
func scimLocalGroupName(selector string) string {
	remainder := strings.TrimPrefix(selector, "group:")
	at := strings.LastIndex(remainder, "@")
	return "group:" + remainder[:at]
}

// domainMatches reports whether domain equals candidate or is a subdomain of
// it, matched ASCII-case-insensitively. A leading "." on candidate is
// tolerated (".example.com" behaves like "example.com"), so an operator who
// writes the suffix form still gets the exact-domain match too.
func domainMatches(domain, candidate string) bool {
	candidate = strings.TrimPrefix(candidate, ".")
	if candidate == "" {
		return false
	}
	if asciiEqualFold(domain, candidate) {
		return true
	}
	return len(domain) > len(candidate)+1 &&
		asciiEqualFold(domain[len(domain)-len(candidate):], candidate) &&
		domain[len(domain)-len(candidate)-1] == '.'
}

// asciiEqualFold compares two domains case-insensitively over ASCII only.
// [strings.EqualFold] applies Unicode simple folding, under which U+017F (long s)
// folds to "s" and U+212A (Kelvin sign) folds to "k" - so "banKexample"
// would match a "bank.example" narrowing. That widens the exemption, which is
// the direction this flag exists to prevent, so the fold is kept to ASCII and
// any non-ASCII byte makes the two domains simply unequal.
func asciiEqualFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range len(a) {
		x, y := a[i], b[i]
		if x >= utf8.RuneSelf || y >= utf8.RuneSelf {
			return false
		}
		if 'A' <= x && x <= 'Z' {
			x += 'a' - 'A'
		}
		if 'A' <= y && y <= 'Z' {
			y += 'a' - 'A'
		}
		if x != y {
			return false
		}
	}
	return true
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

// lintIPSetOperations applies the control plane's explicit-operation rule to
// every ipset: once any member is a remove, a member with no operation word
// has no defined position relative to it, and the policy is rejected at
// upload. The classifier works from the operation word alone, so a set whose
// targets do not all parse is still reported.
func lintIPSetOperations(policy *tailscale.ACL) []LintFinding {
	findings := make([]LintFinding, 0)
	for name, members := range policy.IPSets {
		var implicit *policycore.IPSetImplicitMemberError
		if err := policycore.ValidateIPSetOperations(members); !errors.As(err, &implicit) {
			continue
		}
		locator := "ipsets[" + name + "]"
		findings = append(findings, LintFinding{
			ID:       LintIPSetMixedOperations,
			Severity: LintError,
			Rule:     locator,
			Value:    implicit.Member,
			Evidence: fmt.Sprintf("ipset %s mixes %q, which has no operation, with %q",
				name, implicit.Member, implicit.Remove),
			Remediation: fmt.Sprintf("write it as %q; every member must be an explicit add or remove",
				"add "+implicit.Member),
			Trace: []string{
				fmt.Sprintf("%s carries the operation %q", locator, implicit.Remove),
				fmt.Sprintf("member %q has no add/remove operation", implicit.Member),
				"once any member is a remove, the control plane requires every member to be an explicit operation",
			},
		})
	}
	return findings
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
				"no grant, acl, ssh, group, tagOwner, autoApprovers, nodeAttr (target and app connectors), " +
					"test, or sshTest references " +
					name,
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
	for posture := range policy.Postures {
		if referenced[posture] {
			continue
		}
		findings = append(findings, LintFinding{
			ID:       LintUnusedPosture,
			Severity: LintInfo,
			Rule:     fmt.Sprintf("postures[%s]", posture),
			Value:    posture,
			Evidence: fmt.Sprintf(
				"posture %s is defined but no srcPosture or defaultSrcPosture references it",
				posture,
			),
			Remediation: "reference " + posture + ", or remove the definition",
			Trace: []string{
				fmt.Sprintf("posture %s is defined in postures", posture),
				"no srcPosture or defaultSrcPosture references " + posture,
			},
		})
	}
	return findings
}

// lintPostureExpressions runs every expression in every postures entry through
// policycore/posture's validator. The mapping follows the diagnostic's level:
// unparseable expressions and out-of-vocabulary ip:country values are errors —
// the control plane rejects the policy over both — while an unknown node: or
// ip: attribute only warns, because the known-attribute table is editorial and
// goes stale as the server grows attributes.
func lintPostureExpressions(policy *tailscale.ACL) []LintFinding {
	findings := make([]LintFinding, 0)
	for _, name := range slices.Sorted(maps.Keys(policy.Postures)) {
		for index, expression := range policy.Postures[name] {
			for _, diagnostic := range posture.Validate(expression) {
				findings = append(findings, postureExpressionFinding(name, index, expression, diagnostic))
			}
		}
	}
	return findings
}

func postureExpressionFinding(
	name string, index int, expression string, diagnostic posture.Diagnostic,
) LintFinding {
	locator := fmt.Sprintf("postures[%s][%d]", name, index)
	severity := LintError
	remediation := "correct the expression; the control plane rejects a policy carrying it"
	if !diagnostic.Kind.ErrorLevel() {
		severity = LintWarn
		remediation = "confirm the attribute name; the known-attribute table is editorial " +
			"and may be stale, so this is a warning rather than an error"
	}
	return LintFinding{
		ID:          LintPostureInvalid,
		Severity:    severity,
		Rule:        locator,
		Value:       expression,
		Evidence:    fmt.Sprintf("posture %s expression %q: %s", name, expression, diagnostic.Reason),
		Remediation: remediation,
		Trace: []string{
			fmt.Sprintf("%s defines expression %q", locator, expression),
			diagnostic.Reason,
		},
	}
}

// destination positions are normalized to their host (port stripped); SSH test
// destinations remain node selectors. A definition is unused when its name is
// absent from this set.
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
	addPostureReferences(referenced, policy)
	for _, grant := range policy.Grants {
		addReferences(referenced, grant.Source)
		addReferences(referenced, grant.Destination)
		// via names the subnet routers a grant is routed through, so a
		// definition reachable only from via is used, not unused.
		addReferences(referenced, grant.Via)
	}
	// A node attribute targets the same selectors a grant source does. Omitting
	// it reported a live definition as unused and told the operator to delete
	// it, which tail-acl's own definition removal would then carry out.
	for _, attr := range policy.NodeAttrs {
		addReferences(referenced, attr.Target)
		for _, apps := range attr.App {
			for _, app := range apps {
				if app != nil {
					addReferences(referenced, app.Connectors)
				}
			}
		}
	}
	for _, entry := range policy.ACLs {
		addReferences(referenced, aclSources(entry))
		addDestinationReferences(referenced, aclDestinations(entry))
	}
	for _, members := range policy.Groups {
		addReferences(referenced, members)
	}
	addIPSetMemberReferences(referenced, policy.IPSets)
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

// addPostureReferences marks every posture a rule's srcPosture or the
// tailnet-wide default names as used. Names normalize the way lint's
// reference walk resolves them, so both walks agree on what a reference
// points at.
func addPostureReferences(referenced map[string]bool, policy *tailscale.ACL) {
	add := func(name string) {
		if normalized, err := NormalizePostureName(strings.TrimSpace(name)); err == nil {
			referenced[normalized] = true
		}
	}
	for _, grant := range policy.Grants {
		for _, posture := range grant.SrcPosture {
			add(posture)
		}
	}
	for _, entry := range policy.ACLs {
		for _, posture := range entry.SourcePosture {
			add(posture)
		}
	}
	for _, posture := range policy.DefaultSourcePosture {
		add(posture)
	}
}

// addIPSetMemberReferences counts the ipset: and host: references an ipset
// makes from inside its member list, so a definition used only that way is
// used, not unused. The removal safety walk in DefinitionReferences reads the
// same members.
func addIPSetMemberReferences(referenced map[string]bool, ipsets map[string][]string) {
	for _, members := range ipsets {
		for _, member := range members {
			if definition, ok := ipsetMemberReference(member); ok {
				addReference(referenced, definition)
			}
		}
	}
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
