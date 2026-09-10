package policycore

import (
	tailscale "tailscale.com/client/tailscale/v2"

	"github.com/rshade/tailscale-utils/policycore/alpha"
)

// Policy is a tailnet policy document: the pinned SDK's ACL together with the
// policy fields that SDK does not model. The ACL is embedded, so Groups,
// Hosts, and IPSets stay promoted and the matching walk reads the document
// exactly as it did when Matcher held a bare *tailscale.ACL.
//
// It exists so a hand-modeled policy field has one home rather than widening
// Matcher each time this repository models another. ExternalTailnets is the
// first: declarative node sharing is alpha and tailscale.v2.ACL carries no
// externalTailnets field, a gap alpha's migration tripwire test watches. Once
// the pinned SDK grows one, the field below shadows the promoted one and that
// test fails — the deliberate migration prompt it exists to be.
type Policy struct {
	*tailscale.ACL

	// ExternalTailnets holds the node-sharing relationships this policy
	// declares, keyed by the local alias each is declared under. An alias is
	// a local name, so an alias absent from a map that was actually read is
	// named by nothing in this policy.
	ExternalTailnets alpha.ExternalTailnets

	// HaveExternalTailnets reports that ExternalTailnets was read from the
	// policy document. It draws the distinction HaveRoles draws for the user
	// roster: a nil map with this set means the policy declares no external
	// tailnets, which settles an undeclared alias as a definite non-match,
	// while a nil map with it clear means the caller never parsed the field,
	// which settles nothing. A caller that does not parse externalTailnets
	// must leave it false, or a cross-tailnet selector it cannot evaluate is
	// reported as provably unmatched.
	HaveExternalTailnets bool
}
