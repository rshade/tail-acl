package aclpolicy

import (
	"errors"
	"fmt"
	"strings"

	tailscale "tailscale.com/client/tailscale/v2"
)

// RuleKind identifies the policy section that allowed a reachability query.
type RuleKind string

const (
	// RuleGrant identifies a rule in the policy's grants array.
	RuleGrant RuleKind = "grant"
	// RuleACL identifies a rule in the legacy acls array.
	RuleACL RuleKind = "acl"
)

// RuleReference identifies the rule that allowed a reachability query.
type RuleReference struct {
	Kind  RuleKind `json:"kind"`
	Index int      `json:"index"`
}

// ReachabilityOptions configures EvaluateReachability.
type ReachabilityOptions struct {
	// Strict rejects a policy containing any rule element the evaluator cannot
	// parse, rather than reporting a decision computed while ignoring it.
	Strict bool
}

// ReachabilityResult is the pure, deterministic answer to one network access
// question. Rule is nil when the answer comes from an implicit default rather
// than a matched policy rule. Skipped records malformed rule elements ignored
// in non-strict mode.
type ReachabilityResult struct {
	Allowed     bool           `json:"allowed"`
	Source      string         `json:"source"`
	Destination string         `json:"destination"`
	Port        uint16         `json:"port"`
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

	skipped := scanRules(policy)
	if opts.Strict && len(skipped) != 0 {
		return ReachabilityResult{}, fmt.Errorf(
			"%s (%d unparseable rule(s) in strict mode)",
			skipped[0],
			len(skipped),
		)
	}

	allowed, evidence, trace, rule, err := policyAllows(policy, source, destination)
	if err != nil {
		return ReachabilityResult{}, err
	}
	return ReachabilityResult{
		Allowed:     allowed,
		Source:      source,
		Destination: destination.host,
		Port:        destination.port,
		Rule:        rule,
		Evidence:    evidence,
		Trace:       trace,
		Skipped:     skipped,
	}, nil
}
