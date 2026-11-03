package policycore

import (
	tailscale "tailscale.com/client/tailscale/v2"
)

// Policy is a tailnet policy document: the pinned SDK's ACL together with the
// read flags no SDK can carry. The ACL is embedded, so Groups, Hosts, IPSets,
// and ExternalTailnets stay promoted and the matching walk reads the document
// exactly as it did when Matcher held a bare *tailscale.ACL.
//
// It exists so a hand-modeled policy field has one home rather than widening
// Matcher each time this repository models another. ExternalTailnets was the
// first: declarative node sharing postdated the pinned SDK, and tailscale.v2.ACL carried no
// externalTailnets field until v2.11.0. The SDK models it now, so the
// hand-modeled field is gone and the promoted one serves; what stays here is
// the read flag, which records a fact about the caller rather than the
// document.
type Policy struct {
	*tailscale.ACL

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
