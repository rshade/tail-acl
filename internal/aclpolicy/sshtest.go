package aclpolicy

import tailscale "tailscale.com/client/tailscale/v2"

// SSHTest models a Tailscale SSH policy assertion. tail-acl preserves these
// assertions but does not evaluate them; SSH policy has different targets and
// verdicts from the network-level tests evaluator.
type SSHTest struct {
	Source          string         `json:"src,omitempty"`
	Destination     []string       `json:"dst,omitempty"`
	Accept          []string       `json:"accept,omitempty"`
	Check           []string       `json:"check,omitempty"`
	Deny            []string       `json:"deny,omitempty"`
	SrcPostureAttrs map[string]any `json:"srcPostureAttrs,omitempty"`
}

// SSHRule extends the pinned Tailscale client schema with the documented SSH
// environment-variable allowlist.
type SSHRule struct {
	tailscale.ACLSSH

	AcceptEnv []string `json:"acceptEnv,omitempty"`
}
