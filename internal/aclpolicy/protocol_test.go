package aclpolicy_test

import (
	"strconv"
	"testing"

	tailscale "tailscale.com/client/tailscale/v2"
	"tailscale.com/types/ipproto"

	"github.com/rshade/tail-acl/internal/aclpolicy"
)

// TestKnownIPProtocolsMatchTailscale is the provenance guard for the
// hand-authored protocol vocabulary. Every named and numeric token accepted
// here must remain accepted by the pinned Tailscale implementation, and the
// public evaluator must distinguish known non-port protocols from defects.
//
// Known blind spot: the MarshalText sweep covers ipproto's preferredNames, a
// subset of the acceptedNames map UnmarshalText actually reads (icmpv4,
// icmpv6, tsmp, and ip-in-ip are accepted but never marshalled). A future
// alias added only to acceptedNames would slip past this loop, which is why
// the names slice above is restated by hand. The failure that escapes is
// fail-safe — a spurious skip and a spurious indeterminate, never a wrong
// deny — so this guard is deliberately one-directional.
func TestKnownIPProtocolsMatchTailscale(t *testing.T) {
	t.Parallel()
	names := []string{
		"ah", "dccp", "egp", "esp", "gre", "icmp", "icmpv4", "icmpv6",
		"igmp", "igp", "ip-in-ip", "ipv4", "ipv6-icmp", "sctp", "tcp", "tsmp", "udp",
	}
	for _, name := range names {
		assertKnownProtocol(t, name)
	}
	for number := range 256 {
		assertKnownProtocol(t, strconv.Itoa(number))
		preferred, err := ipproto.Proto(number).MarshalText()
		if err != nil {
			t.Fatalf("MarshalText(%d): %v", number, err)
		}
		assertKnownProtocol(t, string(preferred))
	}
	for _, token := range []string{"TCP", "006", "UDP", "017"} {
		assertKnownProtocol(t, token)
	}

	policy := protocolPolicy("tpc")
	decision, err := aclpolicy.EvaluateReachability(
		policy,
		"alice@example.com",
		"tag:web:443",
		aclpolicy.ReachabilityOptions{},
	)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Access != aclpolicy.AccessIndeterminate || len(decision.Skipped) != 1 {
		t.Errorf("unknown protocol decision = %#v, want one skip and an indeterminate verdict", decision)
	}
}

func assertKnownProtocol(t *testing.T, token string) {
	t.Helper()
	var upstream ipproto.Proto
	if err := upstream.UnmarshalText([]byte(token)); err != nil {
		t.Fatalf("protocol %q is rejected by pinned Tailscale: %v", token, err)
	}
	decision, err := aclpolicy.EvaluateReachability(
		protocolPolicy(token),
		"alice@example.com",
		"tag:web:443",
		aclpolicy.ReachabilityOptions{},
	)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Access == aclpolicy.AccessIndeterminate || len(decision.Skipped) != 0 {
		t.Errorf("known protocol %q treated as unreadable: %#v", token, decision)
	}
}

func protocolPolicy(token string) *tailscale.ACL {
	return &tailscale.ACL{Grants: []tailscale.Grant{{
		Source:      []string{"alice@example.com"},
		Destination: []string{"tag:web"},
		IP:          []string{token + ":443"},
	}}}
}

// Tailscale's ProtoPortRange parses "*", every spelling of protocol 0, and a
// bare port expression into the same value, documented as TCP+UDP+ICMP(4+6).
// Reading "0:443" as a portless protocol made a deny assertion pass over a
// grant that allows the traffic — a confident wrong deny, the failure class
// the three-state verdict exists to remove.
func TestGrantWildcardProtocolSpellingsAgree(t *testing.T) {
	t.Parallel()
	for _, capability := range []string{"*:443", "0:443", "00:443", "000:443", "443", "*"} {
		t.Run(capability, func(t *testing.T) {
			t.Parallel()
			decision, err := aclpolicy.EvaluateReachability(
				&tailscale.ACL{Grants: []tailscale.Grant{{
					Source:      []string{"alice@example.com"},
					Destination: []string{"tag:web"},
					IP:          []string{capability},
				}}},
				"alice@example.com",
				"tag:web:443",
				aclpolicy.ReachabilityOptions{},
			)
			if err != nil {
				t.Fatal(err)
			}
			if decision.Access != aclpolicy.AccessAllow || len(decision.Skipped) != 0 {
				t.Errorf("capability %q = %#v, want a clean allow", capability, decision)
			}
		})
	}
}

// A protocol token the evaluator cannot read is a defect, but it cannot widen
// a port range that already excludes the query — so the narrowing rule still
// rules the capability out. Only a port that could still have matched leaves
// the grant unproven.
func TestUnreadableProtocolStillNarrowsOnPort(t *testing.T) {
	t.Parallel()
	testCases := []struct {
		capability string
		want       aclpolicy.Access
	}{
		{"tpc:80", aclpolicy.AccessDeny},
		{"tpc:443", aclpolicy.AccessIndeterminate},
		{"tpc:*", aclpolicy.AccessIndeterminate},
		{"tpc:htp", aclpolicy.AccessIndeterminate},
		{"tpc:400-500", aclpolicy.AccessIndeterminate},
		{"tpc:1-100", aclpolicy.AccessDeny},
	}
	for _, testCase := range testCases {
		t.Run(testCase.capability, func(t *testing.T) {
			t.Parallel()
			decision, err := aclpolicy.EvaluateReachability(
				&tailscale.ACL{Grants: []tailscale.Grant{{
					Source:      []string{"alice@example.com"},
					Destination: []string{"tag:web"},
					IP:          []string{testCase.capability},
				}}},
				"alice@example.com",
				"tag:web:443",
				aclpolicy.ReachabilityOptions{},
			)
			if err != nil {
				t.Fatal(err)
			}
			if decision.Access != testCase.want {
				t.Errorf("capability %q = %q, want %q", testCase.capability, decision.Access, testCase.want)
			}
			// The defect is reported either way; only the verdict narrows.
			if len(decision.Skipped) != 1 {
				t.Errorf("capability %q Skipped = %#v, want the defect recorded", testCase.capability, decision.Skipped)
			}
		})
	}
}

// SCTP rides the same port-matched path as TCP and UDP in Tailscale's packet
// filter, so a port question can be satisfied by an SCTP capability. DCCP
// reaches the filter's default branch, which needs the entire port range.
func TestSCTPCarriesPortAccess(t *testing.T) {
	t.Parallel()
	testCases := []struct {
		name       string
		capability string
		query      aclpolicy.Protocol
		want       aclpolicy.Access
	}{
		{"sctp answers the agnostic question", "sctp:5432", "", aclpolicy.AccessAllow},
		{"sctp answers its own question", "sctp:5432", aclpolicy.ProtocolSCTP, aclpolicy.AccessAllow},
		{"sctp does not answer for tcp", "sctp:5432", aclpolicy.ProtocolTCP, aclpolicy.AccessDeny},
		{"tcp does not answer for sctp", "tcp:5432", aclpolicy.ProtocolSCTP, aclpolicy.AccessDeny},
		{"numeric sctp is the same protocol", "132:5432", aclpolicy.ProtocolSCTP, aclpolicy.AccessAllow},
		{"dccp carries no port access", "dccp:5432", "", aclpolicy.AccessDeny},
		// Proto 0 expands to TCP+UDP+ICMP(4+6), which excludes SCTP. Every
		// spelling of it must therefore answer the agnostic and TCP questions
		// but refuse SCTP's, or a wildcard grant reports reachable for traffic
		// the packet filter drops.
		{"bare port does not answer for sctp", "5432", aclpolicy.ProtocolSCTP, aclpolicy.AccessDeny},
		{"proto wildcard does not answer for sctp", "*:5432", aclpolicy.ProtocolSCTP, aclpolicy.AccessDeny},
		{"numeric zero does not answer for sctp", "0:5432", aclpolicy.ProtocolSCTP, aclpolicy.AccessDeny},
		{"full wildcard does not answer for sctp", "*", aclpolicy.ProtocolSCTP, aclpolicy.AccessDeny},
		{"bare port still answers the agnostic question", "5432", "", aclpolicy.AccessAllow},
		{"proto wildcard still answers for tcp", "*:5432", aclpolicy.ProtocolTCP, aclpolicy.AccessAllow},
		{"proto wildcard still answers for udp", "*:5432", aclpolicy.ProtocolUDP, aclpolicy.AccessAllow},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			decision, err := aclpolicy.EvaluateReachability(
				&tailscale.ACL{Grants: []tailscale.Grant{{
					Source:      []string{"alice@example.com"},
					Destination: []string{"tag:db"},
					IP:          []string{testCase.capability},
				}}},
				"alice@example.com",
				"tag:db:5432",
				aclpolicy.ReachabilityOptions{Protocol: testCase.query},
			)
			if err != nil {
				t.Fatal(err)
			}
			if decision.Access != testCase.want || len(decision.Skipped) != 0 {
				t.Errorf("%s: %#v, want %q with no skip", testCase.name, decision, testCase.want)
			}
		})
	}
}

// A proto-0 capability rejected for SCTP must not blame the port: its range
// covered the query, and "*" names no protocol to blame either, so the trace
// has to describe the default protocol set. Blaming the port sends a reader to
// widen a range that is already "*".
func TestDefaultProtocolSetMissDoesNotBlameThePort(t *testing.T) {
	t.Parallel()
	for _, capability := range []string{"*", "*:443", "0:443", "443"} {
		t.Run(capability, func(t *testing.T) {
			t.Parallel()
			decision, err := aclpolicy.EvaluateReachability(
				&tailscale.ACL{Grants: []tailscale.Grant{{
					Source:      []string{"alice@example.com"},
					Destination: []string{"tag:web"},
					IP:          []string{capability},
				}}},
				"alice@example.com",
				"tag:web:443",
				aclpolicy.ReachabilityOptions{Protocol: aclpolicy.ProtocolSCTP},
			)
			if err != nil {
				t.Fatal(err)
			}
			if decision.Access != aclpolicy.AccessDeny {
				t.Fatalf("Access = %q, want %q", decision.Access, aclpolicy.AccessDeny)
			}
			want := "grant 0: network capability port 443 matched but " +
				"its default protocol set does not cover sctp"
			if len(decision.Trace) == 0 || decision.Trace[0] != want {
				t.Errorf("Trace[0] = %q, want %q", decision.Trace, want)
			}
		})
	}
}

// A legacy ACL entry with no proto compiles to a filter rule with no IPProto,
// which the packet filter expands to the same default set as a proto-0
// capability. It therefore answers the agnostic and TCP questions but not
// SCTP's, exactly like the grant wildcard above.
func TestLegacyACLWithoutProtocolDoesNotCoverSCTP(t *testing.T) {
	t.Parallel()
	testCases := []struct {
		name  string
		query aclpolicy.Protocol
		want  aclpolicy.Access
	}{
		{"agnostic question", "", aclpolicy.AccessAllow},
		{"tcp question", aclpolicy.ProtocolTCP, aclpolicy.AccessAllow},
		{"udp question", aclpolicy.ProtocolUDP, aclpolicy.AccessAllow},
		{"sctp question", aclpolicy.ProtocolSCTP, aclpolicy.AccessDeny},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			decision, err := aclpolicy.EvaluateReachability(
				&tailscale.ACL{ACLs: []tailscale.ACLEntry{{
					Action:      "accept",
					Source:      []string{"alice@example.com"},
					Destination: []string{"tag:web:443"},
				}}},
				"alice@example.com",
				"tag:web:443",
				aclpolicy.ReachabilityOptions{Protocol: testCase.query},
			)
			if err != nil {
				t.Fatal(err)
			}
			if decision.Access != testCase.want {
				t.Errorf("Access = %q, want %q", decision.Access, testCase.want)
			}
		})
	}
}

// "*" is a ProtoPortRange wildcard, not an ipproto name: it is valid in a
// grants[].ip capability and rejected by acls[].proto. Accepting it in both
// places let an ACL entry match every protocol instead of being reported as
// the policy defect it is.
func TestACLProtocolRejectsTheCapabilityWildcard(t *testing.T) {
	t.Parallel()
	decision, err := aclpolicy.EvaluateReachability(
		&tailscale.ACL{ACLs: []tailscale.ACLEntry{{
			Action:      "accept",
			Source:      []string{"alice@example.com"},
			Destination: []string{"tag:web:443"},
			Protocol:    "*",
		}}},
		"alice@example.com",
		"tag:web:443",
		aclpolicy.ReachabilityOptions{},
	)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Access != aclpolicy.AccessIndeterminate {
		t.Errorf("Access = %q, want %q", decision.Access, aclpolicy.AccessIndeterminate)
	}
	if len(decision.Skipped) != 1 || decision.Skipped[0].Rule != "acls[0].proto" {
		t.Errorf("Skipped = %#v, want the wildcard reported at acls[0].proto", decision.Skipped)
	}
}
