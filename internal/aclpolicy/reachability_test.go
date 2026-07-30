package aclpolicy_test

import (
	"strings"
	"testing"

	tailscale "tailscale.com/client/tailscale/v2"

	"github.com/rshade/tailscale-utils/tail-acl/internal/aclpolicy"
)

// grantPolicy builds a single-grant policy so each case below states only the
// rule element it exercises.
func grantPolicy(grant tailscale.Grant) *tailscale.ACL {
	return &tailscale.ACL{Grants: []tailscale.Grant{grant}}
}

// aclEntryPolicy is grantPolicy's counterpart for the legacy acls array.
func aclEntryPolicy(entry tailscale.ACLEntry) *tailscale.ACL {
	return &tailscale.ACL{ACLs: []tailscale.ACLEntry{entry}}
}

func evaluate(
	t *testing.T,
	policy *tailscale.ACL,
	source, target string,
	opts aclpolicy.ReachabilityOptions,
) aclpolicy.ReachabilityResult {
	t.Helper()
	got, err := aclpolicy.EvaluateReachability(policy, source, target, opts)
	if err != nil {
		t.Fatalf("EvaluateReachability(%q, %q): unexpected error: %v", source, target, err)
	}
	return got
}

// A selector the evaluator cannot resolve must never be reported as a denial.
// autogroup:admin depends on control-plane role data absent from the policy
// file, so the honest answer is "unknown", not "no".
func TestUnresolvableAutogroupSourceIsIndeterminate(t *testing.T) {
	t.Parallel()
	policy := grantPolicy(tailscale.Grant{
		Source:      []string{"autogroup:admin"},
		Destination: []string{"tag:web"},
		IP:          []string{"tcp:443"},
	})

	got := evaluate(t, policy, "alice@example.com", "tag:web:443", aclpolicy.ReachabilityOptions{})

	if got.Access != aclpolicy.AccessIndeterminate {
		t.Errorf("Access = %q, want %q", got.Access, aclpolicy.AccessIndeterminate)
	}
	if got.Allowed != nil {
		t.Errorf(
			"Allowed = %v, want nil; an indeterminate answer must not claim a boolean",
			*got.Allowed,
		)
	}
	if !strings.Contains(got.Evidence, "autogroup:admin") {
		t.Errorf("Evidence = %q, want it to name autogroup:admin", got.Evidence)
	}
	if got.Rule == nil || got.Rule.Kind != aclpolicy.RuleGrant || got.Rule.Index != 0 {
		t.Errorf("Rule = %+v, want the gating grant 0", got.Rule)
	}
}

// An unresolvable selector only clouds the verdict when the rest of the rule
// matches. A grant that fails on destination could never have applied, so the
// answer stays a clean deny rather than degrading every query in the policy.
func TestUnresolvableAutogroupStillDeniesUnrelatedQuery(t *testing.T) {
	t.Parallel()
	policy := grantPolicy(tailscale.Grant{
		Source:      []string{"autogroup:admin"},
		Destination: []string{"tag:web"},
		IP:          []string{"tcp:443"},
	})

	got := evaluate(t, policy, "alice@example.com", "tag:db:5432", aclpolicy.ReachabilityOptions{})

	if got.Access != aclpolicy.AccessDeny {
		t.Errorf("Access = %q, want %q", got.Access, aclpolicy.AccessDeny)
	}
}

// A legacy ACL couples its destination selector to a port in one string, so the
// unresolvable-selector check has to happen after that string is split. It is
// the same blind spot as a grant's dst, and must reach the same verdict.
func TestUnresolvableAutogroupACLDestinationIsIndeterminate(t *testing.T) {
	t.Parallel()
	policy := aclEntryPolicy(tailscale.ACLEntry{
		Action:      "accept",
		Source:      []string{"*"},
		Destination: []string{"autogroup:shared:443"},
	})

	got := evaluate(t, policy, "alice@example.com", "tag:web:443", aclpolicy.ReachabilityOptions{})

	if got.Access != aclpolicy.AccessIndeterminate {
		t.Errorf("Access = %q, want %q", got.Access, aclpolicy.AccessIndeterminate)
	}
	if got.Allowed != nil {
		t.Errorf(
			"Allowed = %v, want nil; an indeterminate answer must not claim a boolean",
			*got.Allowed,
		)
	}
	if !strings.Contains(got.Evidence, "autogroup:shared") {
		t.Errorf("Evidence = %q, want it to name autogroup:shared", got.Evidence)
	}
	if got.Rule == nil || got.Rule.Kind != aclpolicy.RuleACL || got.Rule.Index != 0 {
		t.Errorf("Rule = %+v, want the gating acl 0", got.Rule)
	}
}

// The narrowing rule applies per destination element: the port is a condition
// the evaluator can decide, so an entry ruled out by its port could never have
// applied and its unresolvable selector must not cloud anything.
func TestUnresolvableACLDestinationStillDeniesOnPort(t *testing.T) {
	t.Parallel()
	policy := aclEntryPolicy(tailscale.ACLEntry{
		Action:      "accept",
		Source:      []string{"*"},
		Destination: []string{"autogroup:shared:443"},
	})

	got := evaluate(t, policy, "alice@example.com", "tag:web:9999", aclpolicy.ReachabilityOptions{})

	if got.Access != aclpolicy.AccessDeny {
		t.Errorf("Access = %q, want %q", got.Access, aclpolicy.AccessDeny)
	}
}

// A definite allow outranks an unresolvable rule elsewhere in the policy: the
// question is answered, so the blind spot no longer matters.
func TestDefiniteAllowOutranksUnresolvableRule(t *testing.T) {
	t.Parallel()
	policy := &tailscale.ACL{Grants: []tailscale.Grant{
		{
			Source:      []string{"autogroup:admin"},
			Destination: []string{"tag:web"},
			IP:          []string{"tcp:443"},
		},
		{
			Source:      []string{"alice@example.com"},
			Destination: []string{"tag:web"},
			IP:          []string{"tcp:443"},
		},
	}}

	got := evaluate(t, policy, "alice@example.com", "tag:web:443", aclpolicy.ReachabilityOptions{})

	if got.Access != aclpolicy.AccessAllow {
		t.Errorf("Access = %q, want %q", got.Access, aclpolicy.AccessAllow)
	}
	if got.Rule == nil || got.Rule.Index != 1 {
		t.Errorf("Rule = %+v, want the allowing grant 1", got.Rule)
	}
}

// autogroup:tagged is resolvable from the query alone — a tag: selector is
// tagged and nothing else is — so it must produce a definite verdict.
func TestAutogroupTaggedResolvesLocally(t *testing.T) {
	t.Parallel()
	policy := grantPolicy(tailscale.Grant{
		Source:      []string{"autogroup:tagged"},
		Destination: []string{"tag:web"},
		IP:          []string{"tcp:443"},
	})

	tagged := evaluate(t, policy, "tag:batch", "tag:web:443", aclpolicy.ReachabilityOptions{})
	if tagged.Access != aclpolicy.AccessAllow {
		t.Errorf("tag:batch Access = %q, want %q", tagged.Access, aclpolicy.AccessAllow)
	}

	user := evaluate(t, policy, "alice@example.com", "tag:web:443", aclpolicy.ReachabilityOptions{})
	if user.Access != aclpolicy.AccessDeny {
		t.Errorf("alice@example.com Access = %q, want %q", user.Access, aclpolicy.AccessDeny)
	}
}

// srcPosture and via depend on facts outside the policy snapshot. They were
// previously a hard error; they are now the same third verdict as an
// unresolvable selector, because the situation is identical: the rule would
// have applied but one condition cannot be evaluated here.
func TestUnevaluatableGateIsIndeterminate(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		grant tailscale.Grant
		want  string
	}{
		{
			name: "srcPosture",
			grant: tailscale.Grant{
				Source:      []string{"alice@example.com"},
				Destination: []string{"tag:web"},
				IP:          []string{"tcp:443"},
				SrcPosture:  []string{"posture:latestMac"},
			},
			want: "srcPosture",
		},
		{
			name: "via",
			grant: tailscale.Grant{
				Source:      []string{"alice@example.com"},
				Destination: []string{"tag:web"},
				IP:          []string{"tcp:443"},
				Via:         []string{"tag:router"},
			},
			want: "via",
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			got := evaluate(
				t,
				grantPolicy(testCase.grant),
				"alice@example.com",
				"tag:web:443",
				aclpolicy.ReachabilityOptions{},
			)
			if got.Access != aclpolicy.AccessIndeterminate {
				t.Errorf("Access = %q, want %q", got.Access, aclpolicy.AccessIndeterminate)
			}
			if !strings.Contains(got.Evidence, testCase.want) {
				t.Errorf("Evidence = %q, want it to mention %s", got.Evidence, testCase.want)
			}
		})
	}
}

// A protocol-qualified query must distinguish udp:5432 from tcp:5432. The
// default, ProtocolAny, keeps the protocol-agnostic behaviour that native
// policy tests rely on.
func TestProtocolQualifiedQueryDiscriminates(t *testing.T) {
	t.Parallel()
	policy := grantPolicy(tailscale.Grant{
		Source:      []string{"tag:batch"},
		Destination: []string{"tag:db"},
		IP:          []string{"udp:5432"},
	})
	cases := []struct {
		protocol aclpolicy.Protocol
		want     aclpolicy.Access
	}{
		{aclpolicy.ProtocolUDP, aclpolicy.AccessAllow},
		{aclpolicy.ProtocolTCP, aclpolicy.AccessDeny},
		{aclpolicy.ProtocolAny, aclpolicy.AccessAllow},
		{"", aclpolicy.AccessAllow},
	}
	for _, testCase := range cases {
		t.Run(string(testCase.protocol), func(t *testing.T) {
			t.Parallel()
			got := evaluate(
				t,
				policy,
				"tag:batch",
				"tag:db:5432",
				aclpolicy.ReachabilityOptions{Protocol: testCase.protocol},
			)
			if got.Access != testCase.want {
				t.Errorf("Access = %q, want %q", got.Access, testCase.want)
			}
			if got.Protocol == "" {
				t.Error("Protocol is empty; the result must echo the protocol it answered for")
			}
		})
	}
}

// A bare port capability applies to both protocols, so narrowing the query must
// not turn it into a denial.
func TestBarePortCapabilityMatchesEveryProtocol(t *testing.T) {
	t.Parallel()
	policy := grantPolicy(tailscale.Grant{
		Source:      []string{"tag:batch"},
		Destination: []string{"tag:db"},
		IP:          []string{"5432"},
	})
	for _, protocol := range []aclpolicy.Protocol{
		aclpolicy.ProtocolTCP,
		aclpolicy.ProtocolUDP,
		aclpolicy.ProtocolAny,
	} {
		t.Run(string(protocol), func(t *testing.T) {
			t.Parallel()
			got := evaluate(
				t,
				policy,
				"tag:batch",
				"tag:db:5432",
				aclpolicy.ReachabilityOptions{Protocol: protocol},
			)
			if got.Access != aclpolicy.AccessAllow {
				t.Errorf("Access = %q, want %q", got.Access, aclpolicy.AccessAllow)
			}
		})
	}
}

// The queryable vocabulary is exactly the protocols Tailscale's packet filter
// matches by port. icmp is a real protocol the evaluator still refuses to
// narrow to, because an ICMP rule needs the whole port range and so answers no
// port question; sctp is queryable for the opposite reason.
func TestUnknownProtocolIsRejected(t *testing.T) {
	t.Parallel()
	policy := grantPolicy(tailscale.Grant{
		Source:      []string{"tag:batch"},
		Destination: []string{"tag:db"},
		IP:          []string{"tcp:5432"},
	})
	_, err := aclpolicy.EvaluateReachability(
		policy,
		"tag:batch",
		"tag:db:5432",
		aclpolicy.ReachabilityOptions{Protocol: "icmp"},
	)
	if err == nil || !strings.Contains(err.Error(), "icmp") {
		t.Fatalf("error = %v, want a rejection naming icmp", err)
	}
	if _, err = aclpolicy.EvaluateReachability(
		policy,
		"tag:batch",
		"tag:db:5432",
		aclpolicy.ReachabilityOptions{Protocol: aclpolicy.ProtocolSCTP},
	); err != nil {
		t.Fatalf("error = %v, want sctp to be a queryable protocol", err)
	}
}

// EvaluateTests no longer aborts on an unevaluatable rule; see
// TestEvaluateTestsTreatsUnevaluatableGateAsIndeterminate and
// TestEvaluateTestsReportsIndeterminateWithoutAborting, which replaced this.

// An autogroup nested inside a group is not legal Tailscale policy: group
// members must be full email addresses, and groups cannot contain groups. The
// evaluator therefore treats such a member as an ordinary literal selector that
// simply does not match, rather than clouding the verdict. This test documents
// that deliberate boundary so the behaviour is not mistaken for the
// silent-deny bug that unresolvable autogroups at the rule level do cause.
func TestAutogroupNestedInGroupDoesNotCloudTheVerdict(t *testing.T) {
	t.Parallel()
	policy := grantPolicy(tailscale.Grant{
		Source:      []string{"group:x"},
		Destination: []string{"tag:web"},
		IP:          []string{"tcp:443"},
	})
	policy.Groups = map[string][]string{"group:x": {"autogroup:admin"}}

	got := evaluate(t, policy, "alice@example.com", "tag:web:443", aclpolicy.ReachabilityOptions{})

	if got.Access != aclpolicy.AccessDeny {
		t.Errorf("Access = %q, want %q; an illegal group member must not become a third verdict",
			got.Access, aclpolicy.AccessDeny)
	}
}

// The rule level is the contrast: the same autogroup named directly as a
// grant source is legal policy and must cloud the verdict.
func TestAutogroupAtRuleLevelStillCloudsTheVerdict(t *testing.T) {
	t.Parallel()
	got := evaluate(t, grantPolicy(tailscale.Grant{
		Source:      []string{"autogroup:admin"},
		Destination: []string{"tag:web"},
		IP:          []string{"tcp:443"},
	}), "alice@example.com", "tag:web:443", aclpolicy.ReachabilityOptions{})

	if got.Access != aclpolicy.AccessIndeterminate {
		t.Errorf("Access = %q, want %q", got.Access, aclpolicy.AccessIndeterminate)
	}
}

// --- Query-aware resolvability -------------------------------------------
//
// Whether an autogroup is decidable is a property of the selector AND the
// query, not the selector alone. autogroup:tagged is decidable against a tag
// and against a user, but not against an IP: deciding that needs the
// device->tag map, which lives in the control plane.

func TestResolvabilityDependsOnTheQuery(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		selector string
		query    string
		want     aclpolicy.Access
	}{
		{"tagged vs tag is decidable", "autogroup:tagged", "tag:batch", aclpolicy.AccessAllow},
		{
			"tagged vs user is decidable",
			"autogroup:tagged",
			"alice@example.com",
			aclpolicy.AccessDeny,
		},
		{
			"tagged vs IP needs the control plane",
			"autogroup:tagged",
			"100.64.0.9",
			aclpolicy.AccessIndeterminate,
		},
		{
			"member vs user is decidable",
			"autogroup:member",
			"alice@example.com",
			aclpolicy.AccessAllow,
		},
		{"member vs tag is decidable", "autogroup:member", "tag:batch", aclpolicy.AccessDeny},
		{
			"member vs IP needs the control plane",
			"autogroup:member",
			"100.64.0.9",
			aclpolicy.AccessIndeterminate,
		},
		// A role autogroup contains only users, so a tagged source is refutable
		// with certainty. Reporting indeterminate for a settleable question
		// trains callers to ignore exit 10.
		{"admin vs tag is decidable", "autogroup:admin", "tag:batch", aclpolicy.AccessDeny},
		{
			"admin vs user needs the control plane",
			"autogroup:admin",
			"alice@example.com",
			aclpolicy.AccessIndeterminate,
		},
		{
			"admin vs IP needs the control plane",
			"autogroup:admin",
			"100.64.0.9",
			aclpolicy.AccessIndeterminate,
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			got := evaluate(t, grantPolicy(tailscale.Grant{
				Source:      []string{testCase.selector},
				Destination: []string{"tag:web"},
				IP:          []string{"tcp:443"},
			}), testCase.query, "tag:web:443", aclpolicy.ReachabilityOptions{})
			if got.Access != testCase.want {
				t.Errorf(
					"Access = %q, want %q (evidence: %s)",
					got.Access,
					testCase.want,
					got.Evidence,
				)
			}
		})
	}
}

// A host alias resolves to an address, so it inherits that address's
// undecidability rather than being treated as an opaque literal.
func TestResolvabilityFollowsHostAliases(t *testing.T) {
	t.Parallel()
	policy := grantPolicy(tailscale.Grant{
		Source:      []string{"autogroup:tagged"},
		Destination: []string{"tag:web"},
		IP:          []string{"tcp:443"},
	})
	policy.Hosts = map[string]string{"batchbox": "100.64.0.9"}

	got := evaluate(t, policy, "batchbox", "tag:web:443", aclpolicy.ReachabilityOptions{})

	if got.Access != aclpolicy.AccessIndeterminate {
		t.Errorf("Access = %q, want %q", got.Access, aclpolicy.AccessIndeterminate)
	}
}

// --- An unparseable sibling must not manufacture certainty ----------------
//
// A malformed element and an unresolvable selector are two independent reasons
// for doubt. Composing them into a confident denial is the bug this locks out.

func TestUnparseableSiblingDoesNotSwallowTheGate(t *testing.T) {
	t.Parallel()
	t.Run("acl destination", func(t *testing.T) {
		t.Parallel()
		policy := &tailscale.ACL{ACLs: []tailscale.ACLEntry{{
			Action:      "accept",
			Source:      []string{"*"},
			Destination: []string{"autogroup:shared:443", "tag:web"}, // second entry has no port
		}}}
		got := evaluate(
			t,
			policy,
			"alice@example.com",
			"tag:web:443",
			aclpolicy.ReachabilityOptions{},
		)
		if got.Access != aclpolicy.AccessIndeterminate {
			t.Errorf("Access = %q, want %q", got.Access, aclpolicy.AccessIndeterminate)
		}
	})
	t.Run("grant capability", func(t *testing.T) {
		t.Parallel()
		got := evaluate(t, grantPolicy(tailscale.Grant{
			Source:      []string{"autogroup:admin"},
			Destination: []string{"tag:web"},
			IP:          []string{"tcp:44x"}, // malformed port
		}), "alice@example.com", "tag:web:443", aclpolicy.ReachabilityOptions{})
		if got.Access != aclpolicy.AccessIndeterminate {
			t.Errorf("Access = %q, want %q", got.Access, aclpolicy.AccessIndeterminate)
		}
	})
}

func TestUnparseableRuleAloneIsIndeterminate(t *testing.T) {
	t.Parallel()
	t.Run("acl destination", func(t *testing.T) {
		t.Parallel()
		got := evaluate(t, aclEntryPolicy(tailscale.ACLEntry{
			Action:      "accept",
			Source:      []string{"alice@example.com"},
			Destination: []string{"tag:web"},
		}), "alice@example.com", "tag:web:443", aclpolicy.ReachabilityOptions{})
		if got.Access != aclpolicy.AccessIndeterminate {
			t.Errorf("Access = %q, want %q", got.Access, aclpolicy.AccessIndeterminate)
		}
	})
	t.Run("grant capability", func(t *testing.T) {
		t.Parallel()
		got := evaluate(t, grantPolicy(tailscale.Grant{
			Source:      []string{"alice@example.com"},
			Destination: []string{"tag:web"},
			IP:          []string{"tcp:htp"},
		}), "alice@example.com", "tag:web:443", aclpolicy.ReachabilityOptions{})
		if got.Access != aclpolicy.AccessIndeterminate {
			t.Errorf("Access = %q, want %q", got.Access, aclpolicy.AccessIndeterminate)
		}
	})
}

func TestACLProtocolVocabularySeparatesUnknownFromNonPort(t *testing.T) {
	t.Parallel()
	testCases := []struct {
		name        string
		protocol    string
		destination string
		want        aclpolicy.Access
		wantSkip    bool
	}{
		{"unknown overlapping", "stcp", "tag:web:443", aclpolicy.AccessIndeterminate, true},
		{"unknown destination narrowed", "stcp", "tag:other:443", aclpolicy.AccessDeny, true},
		// sctp rides the same port-matched filter path as tcp and udp, so it
		// answers a port question; dccp reaches the filter's default branch,
		// which needs the entire port range, so it genuinely cannot.
		{"known port-carrying", "sctp", "tag:web:443", aclpolicy.AccessAllow, false},
		{"known non-port", "dccp", "tag:web:443", aclpolicy.AccessDeny, false},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			got := evaluate(t, aclEntryPolicy(tailscale.ACLEntry{
				Action:      "accept",
				Source:      []string{"alice@example.com"},
				Destination: []string{"tag:web:443"},
				Protocol:    testCase.protocol,
			}), "alice@example.com", testCase.destination, aclpolicy.ReachabilityOptions{})
			if got.Access != testCase.want {
				t.Errorf("Access = %q, want %q", got.Access, testCase.want)
			}
			if (len(got.Skipped) != 0) != testCase.wantSkip {
				t.Errorf("Skipped = %#v, wantSkip %t", got.Skipped, testCase.wantSkip)
			}
		})
	}
}

// The narrowing rule still governs: a port the evaluator CAN decide rules the
// rule out, so a gate elsewhere on it must not resurface.
func TestDecidablePortMismatchStillNarrows(t *testing.T) {
	t.Parallel()
	got := evaluate(t, grantPolicy(tailscale.Grant{
		Source:      []string{"autogroup:admin"},
		Destination: []string{"tag:web"},
		IP:          []string{"tcp:443"},
	}), "alice@example.com", "tag:web:9999", aclpolicy.ReachabilityOptions{})

	if got.Access != aclpolicy.AccessDeny {
		t.Errorf("Access = %q, want %q", got.Access, aclpolicy.AccessDeny)
	}
}

// autogroup:danger-all matches the pre-mitigation meaning of "*" — every
// device, including ones outside the tailnet. It is valid in src and it is
// meant to match everything there, so a wide-open grant must read as reachable
// rather than being hidden behind a denial.
func TestDangerAllMatchesEverySource(t *testing.T) {
	t.Parallel()
	got := evaluate(t, grantPolicy(tailscale.Grant{
		Source:      []string{"autogroup:danger-all"},
		Destination: []string{"tag:db"},
		IP:          []string{"tcp:5432"},
	}), "attacker@evil.example", "tag:db:5432", aclpolicy.ReachabilityOptions{})

	if got.Access != aclpolicy.AccessAllow {
		t.Errorf("Access = %q, want %q; danger-all must not hide an over-permissive grant",
			got.Access, aclpolicy.AccessAllow)
	}
}

// --- EvaluateTests must not discard a whole report ------------------------

// An assertion the evaluator genuinely cannot settle is reported as its own
// status, not as an error that throws away every assertion already computed.
// Aborting turned one autogroup:admin grant — present in essentially every real
// tailnet policy — into exit 2 with an empty report.
func TestEvaluateTestsReportsIndeterminateWithoutAborting(t *testing.T) {
	t.Parallel()
	policy := &tailscale.ACL{Grants: []tailscale.Grant{
		{
			Source:      []string{"alice@example.com"},
			Destination: []string{"tag:db"},
			IP:          []string{"tcp:5432"},
		},
		{
			Source:      []string{"autogroup:admin"},
			Destination: []string{"tag:audit"},
			IP:          []string{"tcp:8443"},
		},
	}}
	policy.Tests = []tailscale.ACLTest{
		{Source: "alice@example.com", Accept: []string{"tag:db:5432"}},
		{Source: "alice@example.com", Deny: []string{"tag:audit:8443"}},
	}

	report, err := aclpolicy.EvaluateTests(policy, aclpolicy.TestOptions{})
	if err != nil {
		t.Fatalf("EvaluateTests returned an error instead of a report: %v", err)
	}

	if len(report.Assertions) != 2 {
		t.Fatalf(
			"got %d assertions, want 2 — the decidable one must survive",
			len(report.Assertions),
		)
	}
	if report.Assertions[0].Status != aclpolicy.AssertionPass {
		t.Errorf(
			"assertions[0].Status = %q, want %q",
			report.Assertions[0].Status,
			aclpolicy.AssertionPass,
		)
	}
	if report.Assertions[1].Status != aclpolicy.AssertionIndeterminate {
		t.Errorf("assertions[1].Status = %q, want %q",
			report.Assertions[1].Status, aclpolicy.AssertionIndeterminate)
	}
	if report.Summary.Indeterminate != 1 || report.Summary.Total != 2 {
		t.Errorf("Summary = %+v, want Total 2 with 1 indeterminate", report.Summary)
	}
}

// srcPosture and via reach the same path, so they must behave the same way
// rather than remaining a hard error.
func TestEvaluateTestsTreatsUnevaluatableGateAsIndeterminate(t *testing.T) {
	t.Parallel()
	policy := grantPolicy(tailscale.Grant{
		Source:      []string{"alice@example.com"},
		Destination: []string{"tag:web"},
		IP:          []string{"tcp:443"},
		Via:         []string{"tag:router"},
	})
	policy.Tests = []tailscale.ACLTest{
		{Source: "alice@example.com", Accept: []string{"tag:web:443"}},
	}

	report, err := aclpolicy.EvaluateTests(policy, aclpolicy.TestOptions{})
	if err != nil {
		t.Fatalf("EvaluateTests: %v", err)
	}
	if len(report.Assertions) != 1 ||
		report.Assertions[0].Status != aclpolicy.AssertionIndeterminate {
		t.Fatalf("assertions = %+v, want one indeterminate", report.Assertions)
	}
	if !strings.Contains(report.Assertions[0].Evidence, "via") {
		t.Errorf("Evidence = %q, want it to name via routing", report.Assertions[0].Evidence)
	}
}
