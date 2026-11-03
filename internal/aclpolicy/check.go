package aclpolicy

import (
	"errors"
	"fmt"
	"strings"

	tailscale "tailscale.com/client/tailscale/v2"

	"github.com/rshade/tail-acl/pkg/policycore"
	"github.com/rshade/tail-acl/pkg/policycore/posture"
)

// RuleKind identifies the policy section holding the rule that decided a
// reachability query.
type RuleKind string

const (
	// RuleGrant identifies a rule in the policy's grants array.
	RuleGrant RuleKind = "grant"
	// RuleACL identifies a rule in the legacy acls array.
	RuleACL RuleKind = "acl"
)

// RuleReference identifies the rule that decided a reachability query: the one
// that allowed it, or — for an indeterminate answer — the one whose
// unevaluatable condition prevented a verdict.
type RuleReference struct {
	Kind  RuleKind `json:"kind"`
	Index int      `json:"index"`
}

// Access is the three-state answer to a reachability question. The third state
// exists because a policy file does not contain every fact a verdict can depend
// on: device posture, via routing, and role autogroups such as autogroup:admin
// live in the control plane. Collapsing "cannot tell" into "deny" would report
// a confident denial the policy does not support.
type Access string

const (
	// AccessAllow means a rule matched and nothing gated it.
	AccessAllow Access = "allow"
	// AccessDeny means no rule matched and nothing was left unresolved.
	AccessDeny Access = "deny"
	// AccessIndeterminate means a rule would have matched but depends on a fact
	// outside the policy file.
	AccessIndeterminate Access = "indeterminate"
)

// Protocol narrows a reachability question to one IP protocol. ProtocolAny is
// the default and asks whether any port-carrying protocol is allowed, which is
// the question native policy tests ask.
type Protocol string

const (
	// ProtocolAny matches a capability for any port-carrying protocol.
	ProtocolAny Protocol = "any"
	// ProtocolTCP matches only TCP capabilities.
	ProtocolTCP Protocol = "tcp"
	// ProtocolUDP matches only UDP capabilities.
	ProtocolUDP Protocol = "udp"
	// ProtocolSCTP matches only SCTP capabilities. Tailscale's packet filter
	// matches SCTP on the same port-carrying path as TCP and UDP
	// (wgengine/filter/filter.go), so a port question can be satisfied by an
	// SCTP capability; protocols that reach the filter's default branch instead
	// need the whole port range and so carry no port access.
	ProtocolSCTP Protocol = "sctp"
)

// normalize resolves the empty zero value to ProtocolAny and reports whether
// the protocol is one the evaluator can answer for.
func (p Protocol) normalize() (Protocol, bool) {
	switch p {
	case "", ProtocolAny:
		return ProtocolAny, true
	case ProtocolTCP, ProtocolUDP, ProtocolSCTP:
		return p, true
	default:
		return p, false
	}
}

// ReachabilityOptions configures EvaluateReachability.
type ReachabilityOptions struct {
	// Strict rejects a policy containing any rule element the evaluator cannot
	// parse, rather than reporting a decision computed while ignoring it.
	Strict bool
	// Protocol narrows the question to one IP protocol. The zero value asks
	// about any port-carrying protocol — TCP, UDP, or SCTP — matching native
	// policy tests.
	Protocol Protocol
	// Roster maps a lowercased login to its tailnet role, resolving the role
	// autogroups the policy file alone cannot decide. Build it with
	// policycore.ParseRoster, which owns the lowercasing this lookup requires.
	//
	// A non-nil Roster asserts the roster is complete and authoritative, so a
	// login it does not list is a definite non-match. An empty-but-non-nil map
	// therefore means "the tailnet was read and nobody holds a role", which is
	// a real answer; nil means no roster was supplied. That is why this is one
	// nilable map rather than a map beside a HaveRoles bool: a caller cannot
	// set the roster and forget the flag, because there is no separate flag to
	// forget.
	Roster map[string]tailscale.UserRole
	// PostureAttrs carries the posture attributes the query asks with,
	// keyed as the policy names them ("node:os", "custom:deviceApproved").
	// A nil map means no attributes were supplied, and a posture gate keeps
	// the legacy indeterminate behavior.
	PostureAttrs map[string]any
	// PostureAttrsComplete asserts PostureAttrs is authoritative: an
	// attribute it omits is definitely unset, so NOT SET matches it and every
	// other comparison fails. Without it an omitted attribute the gate needs
	// is indeterminate — for a question about a real device, "not supplied"
	// means "not known", not "unset".
	PostureAttrsComplete bool
}

// ReachabilityResult is the pure, deterministic answer to one network access
// question. Rule names the rule that decided the answer and is nil whenever no
// single rule did — a plain default deny, or the implicit default-allow policy.
// Skipped records malformed rule elements ignored in non-strict mode.
type ReachabilityResult struct {
	Access Access `json:"access"`
	// Allowed is the older two-state field, kept for existing consumers. It is
	// nil — and omitted from JSON — for an indeterminate answer, because
	// serializing false beside access:"indeterminate" hands a consumer that
	// reads only this key a denial the evaluator never concluded. Read Access.
	Allowed     *bool          `json:"allowed,omitempty"`
	Source      string         `json:"source"`
	Destination string         `json:"destination"`
	Port        uint16         `json:"port"`
	Protocol    Protocol       `json:"protocol"`
	Rule        *RuleReference `json:"rule,omitempty"`
	Evidence    string         `json:"evidence"`
	Trace       []string       `json:"trace"`
	Skipped     []RuleSkip     `json:"skipped,omitempty"`
}

// EvaluateReachability answers whether source can reach target under policy's
// network-level grants and legacy ACLs without contacting the control plane.
// target must use host:port syntax; IPv6 addresses use [ipv6]:port.
func EvaluateReachability(
	policy *tailscale.ACL,
	source, targetValue string,
	opts ReachabilityOptions,
) (ReachabilityResult, error) {
	if policy == nil {
		return ReachabilityResult{}, errors.New("policy is nil")
	}
	source = strings.TrimSpace(source)
	if source == "" {
		return ReachabilityResult{}, errors.New("source is empty")
	}
	destination, err := parseTarget(targetValue)
	if err != nil {
		return ReachabilityResult{}, err
	}

	protocol, ok := opts.Protocol.normalize()
	if !ok {
		return ReachabilityResult{}, fmt.Errorf(
			"unknown protocol %q; want %s, %s, %s, or %s",
			opts.Protocol, ProtocolTCP, ProtocolUDP, ProtocolSCTP, ProtocolAny,
		)
	}

	// HaveExternalTailnets stays false: this loader does not parse
	// externalTailnets, so a cross-tailnet selector stays Unresolvable.
	matcher := policycore.Matcher{
		Policy:    &policycore.Policy{ACL: policy},
		Roles:     opts.Roster,
		HaveRoles: opts.Roster != nil,
	}
	skipped := scanRules(matcher)
	if opts.Strict && len(skipped) != 0 {
		return ReachabilityResult{}, fmt.Errorf(
			"%s (%d unparseable rule(s) in strict mode)",
			skipped[0],
			len(skipped),
		)
	}

	decision := policyAllows(
		matcher, source, destination, protocol,
		posture.Attrs{Map: opts.PostureAttrs, Complete: opts.PostureAttrsComplete},
	)
	var allowed *bool
	if decision.access != AccessIndeterminate {
		settled := decision.access == AccessAllow
		allowed = &settled
	}
	return ReachabilityResult{
		Access:      decision.access,
		Allowed:     allowed,
		Source:      source,
		Destination: destination.host,
		Port:        destination.port,
		Protocol:    protocol,
		Rule:        decision.rule,
		Evidence:    decision.evidence,
		Trace:       decision.trace,
		Skipped:     skipped,
	}, nil
}
