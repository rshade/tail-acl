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

// postureGatePolicy builds a policy with one posture-gated grant and the
// postures it references, so each case states only the attributes it asks
// with.
func postureGatePolicy() *tailscale.ACL {
	return &tailscale.ACL{
		Postures: map[string][]string{
			"posture:steering": {"custom:subnet_router NOT SET", "ip:country NOT IN ['KP', 'IR']"},
			"posture:geo-free": {"custom:subnet_router NOT SET", "ip:country NOT SET"},
		},
		Grants: []tailscale.Grant{{
			Source:      []string{"alice@example.com"},
			Destination: []string{"tag:web"},
			IP:          []string{"tcp:443"},
			SrcPosture:  []string{"posture:steering", "posture:geo-free"},
		}},
	}
}

// TestPostureGateEvaluatesWithSuppliedAttrs pins the three outcomes of
// posture-gate evaluation: a satisfied posture opens the gate (allow), every
// posture failing closes it decidably (deny, with the trace naming the
// deciding expression and attribute), and an unevaluable gate keeps the
// indeterminate verdict with wording distinct from the legacy attr-less gate.
func TestPostureGateEvaluatesWithSuppliedAttrs(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name         string
		attrs        map[string]any
		complete     bool
		wantAccess   aclpolicy.Access
		evidenceHas  []string
		traceHas     []string
		traceMissing []string
	}{
		{
			name:        "a satisfied posture opens the gate",
			attrs:       map[string]any{"ip:country": "US"},
			complete:    true,
			wantAccess:  aclpolicy.AccessAllow,
			evidenceHas: []string{"matched grant 0"},
			traceHas: []string{
				"custom:subnet_router is unset",
				"ip:country US is not in ['KP', 'IR']",
				"so posture:steering holds",
			},
		},
		{
			name:        "every posture failing closes the gate decidably",
			attrs:       map[string]any{"ip:country": "KP"},
			complete:    true,
			wantAccess:  aclpolicy.AccessDeny,
			evidenceHas: []string{"no network grant or ACL matched"},
			traceHas: []string{
				"posture gate did not match",
				"ip:country KP is in ['KP', 'IR'], so posture:steering fails",
				"ip:country is set, so posture:geo-free fails",
			},
		},
		{
			name:       "an unsupplied attribute without completeness is indeterminate",
			attrs:      map[string]any{"ip:country": "KP"},
			complete:   false,
			wantAccess: aclpolicy.AccessIndeterminate,
			evidenceHas: []string{
				"posture could not be evaluated locally",
				"custom:subnet_router was not supplied",
			},
			traceMissing: []string{"uses unsupported srcPosture"},
		},
		{
			name:       "a partial set that fully decides the gate denies",
			attrs:      map[string]any{"custom:subnet_router": "nyc", "ip:country": "US"},
			complete:   false,
			wantAccess: aclpolicy.AccessDeny,
			traceHas: []string{
				"posture gate did not match",
				"custom:subnet_router is set, so posture:steering fails",
			},
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			got := evaluate(t, postureGatePolicy(), "alice@example.com", "tag:web:443",
				aclpolicy.ReachabilityOptions{
					PostureAttrs:         testCase.attrs,
					PostureAttrsComplete: testCase.complete,
				})
			assertPostureGateOutcome(t, got, testCase)
		})
	}
}

func assertPostureGateOutcome(
	t *testing.T,
	got aclpolicy.ReachabilityResult,
	testCase struct {
		name         string
		attrs        map[string]any
		complete     bool
		wantAccess   aclpolicy.Access
		evidenceHas  []string
		traceHas     []string
		traceMissing []string
	},
) {
	t.Helper()
	if got.Access != testCase.wantAccess {
		t.Errorf("Access = %q, want %q (evidence %q)", got.Access, testCase.wantAccess, got.Evidence)
	}
	joined := strings.Join(append([]string{got.Evidence}, got.Trace...), "\n")
	for _, fragment := range testCase.evidenceHas {
		if !strings.Contains(joined, fragment) {
			t.Errorf("evidence/trace does not contain %q:\n%s", fragment, joined)
		}
	}
	trace := strings.Join(got.Trace, "\n")
	for _, fragment := range testCase.traceHas {
		if !strings.Contains(trace, fragment) {
			t.Errorf("trace does not contain %q:\n%s", fragment, trace)
		}
	}
	for _, fragment := range testCase.traceMissing {
		if strings.Contains(joined, fragment) {
			t.Errorf("evidence/trace unexpectedly contains %q:\n%s", fragment, joined)
		}
	}
}

// TestPostureGateUnevaluableExpressions pins the always-indeterminate
// expressions: an unparseable expression (also reported in the policy-scoped
// skipped list) and a version comparison.
func TestPostureGateUnevaluableExpressions(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name        string
		postures    map[string][]string
		attrs       map[string]any
		evidenceHas []string
		wantSkipped bool
	}{
		{
			name: "unparseable expression",
			postures: map[string][]string{
				"posture:broken": {"this is not an expression"},
			},
			attrs: map[string]any{"node:os": "linux"},
			evidenceHas: []string{
				"posture could not be evaluated locally",
				"unsupported posture expression",
			},
			wantSkipped: true,
		},
		{
			name: "version comparison",
			postures: map[string][]string{
				"posture:versioned": {"node:tsVersion >= '1.8'"},
			},
			attrs: map[string]any{"node:tsVersion": "1.98.8"},
			evidenceHas: []string{
				"posture could not be evaluated locally",
				"version comparison",
			},
		},
		{
			name: "undefined posture",
			postures: map[string][]string{
				"posture:other": {"node:os == 'linux'"},
			},
			attrs: map[string]any{"node:os": "linux"},
			evidenceHas: []string{
				"posture could not be evaluated locally",
				"posture:gated is not defined in postures",
			},
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			policy := &tailscale.ACL{
				Postures: testCase.postures,
				Grants: []tailscale.Grant{{
					Source:      []string{"alice@example.com"},
					Destination: []string{"tag:web"},
					IP:          []string{"tcp:443"},
					SrcPosture:  []string{"posture:broken", "posture:versioned", "posture:gated"},
				}},
			}
			got := evaluate(t, policy, "alice@example.com", "tag:web:443",
				aclpolicy.ReachabilityOptions{
					PostureAttrs:         testCase.attrs,
					PostureAttrsComplete: true,
				})
			if got.Access != aclpolicy.AccessIndeterminate {
				t.Errorf("Access = %q, want %q (evidence %q)",
					got.Access, aclpolicy.AccessIndeterminate, got.Evidence)
			}
			for _, fragment := range testCase.evidenceHas {
				if !strings.Contains(got.Evidence, fragment) {
					t.Errorf("Evidence = %q, want it to contain %q", got.Evidence, fragment)
				}
			}
			if testCase.wantSkipped {
				if len(got.Skipped) != 1 || got.Skipped[0].Rule != "postures[posture:broken][0]" {
					t.Errorf("Skipped = %#v, want the unparseable posture expression", got.Skipped)
				}
			}
		})
	}
}

// defaultSrcPosture gates every rule that does not set its own srcPosture,
// and the evidence says where the gate came from, since the rule itself
// carries no posture field a reader could find. A rule with its own
// srcPosture replaces the default rather than adding to it.
func TestDefaultSrcPostureGatesRulesWithoutTheirOwn(t *testing.T) {
	t.Parallel()
	defaultPolicy := func() *tailscale.ACL {
		return &tailscale.ACL{
			DefaultSourcePosture: []string{"posture:linux"},
			Grants: []tailscale.Grant{{
				Source:      []string{"alice@example.com"},
				Destination: []string{"tag:web"},
				IP:          []string{"tcp:443"},
			}},
		}
	}

	t.Run("grant gated by the default names its origin", func(t *testing.T) {
		t.Parallel()
		got := evaluate(t, defaultPolicy(), "alice@example.com", "tag:web:443", aclpolicy.ReachabilityOptions{})
		if got.Access != aclpolicy.AccessIndeterminate {
			t.Errorf("Access = %q, want %q", got.Access, aclpolicy.AccessIndeterminate)
		}
		if !strings.Contains(got.Evidence, "uses unsupported srcPosture (from defaultSrcPosture)") {
			t.Errorf("Evidence = %q, want the default-origin gate text", got.Evidence)
		}
	})

	t.Run("own srcPosture replaces the default", func(t *testing.T) {
		t.Parallel()
		policy := defaultPolicy()
		policy.Grants[0].SrcPosture = []string{"posture:own"}
		got := evaluate(t, policy, "alice@example.com", "tag:web:443", aclpolicy.ReachabilityOptions{})
		if !strings.Contains(got.Evidence, "uses unsupported srcPosture") {
			t.Errorf("Evidence = %q, want the posture gate", got.Evidence)
		}
		if strings.Contains(got.Evidence, "from defaultSrcPosture") {
			t.Errorf("Evidence = %q, want no default origin for a rule's own posture", got.Evidence)
		}
	})

	t.Run("acl entry gated by the default names its origin", func(t *testing.T) {
		t.Parallel()
		policy := aclEntryPolicy(tailscale.ACLEntry{
			Action:      "accept",
			Source:      []string{"alice@example.com"},
			Destination: []string{"tag:web:443"},
		})
		policy.DefaultSourcePosture = []string{"posture:linux"}
		got := evaluate(t, policy, "alice@example.com", "tag:web:443", aclpolicy.ReachabilityOptions{})
		if got.Access != aclpolicy.AccessIndeterminate {
			t.Errorf("Access = %q, want %q", got.Access, aclpolicy.AccessIndeterminate)
		}
		if !strings.Contains(got.Evidence, "uses unsupported srcPosture (from defaultSrcPosture)") {
			t.Errorf("Evidence = %q, want the default-origin gate text", got.Evidence)
		}
	})

	t.Run("no default keeps the definite verdict", func(t *testing.T) {
		t.Parallel()
		policy := grantPolicy(tailscale.Grant{
			Source:      []string{"alice@example.com"},
			Destination: []string{"tag:web"},
			IP:          []string{"tcp:443"},
		})
		got := evaluate(t, policy, "alice@example.com", "tag:web:443", aclpolicy.ReachabilityOptions{})
		if got.Access != aclpolicy.AccessAllow {
			t.Errorf("Access = %q, want %q", got.Access, aclpolicy.AccessAllow)
		}
	})
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

// Even if the control plane would reject this group member, policycore recurses
// groups while matching and must recurse them while deciding whether a miss is
// conclusive. Otherwise an unevaluable nested autogroup becomes a confident
// deny while the same selector at rule level correctly yields indeterminate.
func TestAutogroupNestedInGroupCloudsTheVerdict(t *testing.T) {
	t.Parallel()
	policy := grantPolicy(tailscale.Grant{
		Source:      []string{"group:x"},
		Destination: []string{"tag:web"},
		IP:          []string{"tcp:443"},
	})
	policy.Groups = map[string][]string{"group:x": {"autogroup:admin"}}

	got := evaluate(t, policy, "alice@example.com", "tag:web:443", aclpolicy.ReachabilityOptions{})

	if got.Access != aclpolicy.AccessIndeterminate {
		t.Errorf("Access = %q, want %q", got.Access, aclpolicy.AccessIndeterminate)
	}
}

// The same autogroup named directly as a grant source must cloud the verdict.
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

// A cross-tailnet selector names members of another tailnet, whose roster this
// policy file cannot supply, so it degrades the verdict the same way an
// unresolvable autogroup does. Before policycore recognized the grammar this
// query returned a confident deny, which is the wrong answer rather than a
// missing one.
func TestCrossTailnetSourceSelectorIsIndeterminate(t *testing.T) {
	t.Parallel()
	policy := grantPolicy(tailscale.Grant{
		Source:      []string{"group://partner/engineering"},
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
	if !strings.Contains(got.Evidence, "group://partner/engineering") {
		t.Errorf("Evidence = %q, want it to name the cross-tailnet selector", got.Evidence)
	}
}

// --- ipset member forms (#366) --------------------------------------------
//
// The control plane enforces an ipset written with add/remove operations, a
// range, or a host: reference exactly as written. The resolver used to pass
// those members through verbatim, so every address inside such a set was a
// confident false deny. These are the four rows #366 measured.

func issue366Policy() *tailscale.ACL {
	policy := grantPolicy(tailscale.Grant{
		Source:      []string{"tag:web"},
		Destination: []string{"ipset:trimmed", "ipset:rng", "ipset:h"},
		IP:          []string{"tcp:*"},
	})
	policy.Hosts = map[string]string{"gw": "10.9.0.1"}
	policy.IPSets = map[string][]string{
		"ipset:base":    {"10.0.0.0/8"},
		"ipset:trimmed": {"add ipset:base", "remove 10.1.0.0/16"},
		"ipset:rng":     {"10.5.0.1-10.5.0.9"},
		"ipset:h":       {"host:gw"},
	}
	return policy
}

func TestIPSetMemberFormsResolveInAVerdict(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		target string
		want   aclpolicy.Access
	}{
		{"removed from the set", "10.1.0.5:80", aclpolicy.AccessDeny},
		{"kept by the add", "10.2.0.5:80", aclpolicy.AccessAllow},
		{"inside the range", "10.5.0.4:81", aclpolicy.AccessAllow},
		{"the host alias", "10.9.0.1:82", aclpolicy.AccessAllow},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			got := evaluate(t, issue366Policy(), "tag:web", testCase.target, aclpolicy.ReachabilityOptions{})
			if got.Access != testCase.want {
				t.Fatalf("Access = %q, want %q; evidence: %s", got.Access, testCase.want, got.Evidence)
			}
			if got.Access != aclpolicy.AccessAllow {
				return
			}
			if got.Rule == nil || got.Rule.Kind != aclpolicy.RuleGrant || got.Rule.Index != 0 {
				t.Errorf("Rule = %+v, want the matched grant 0", got.Rule)
			}
		})
	}
}

// A defined ipset the resolver cannot materialize — here a host: reference to
// nothing — is a fact the policy file cannot supply, so it clouds the verdict
// rather than denying it. An undefined ipset: selector, by contrast, still
// names nothing.
func TestGrantToAnUnmaterializableIPSetIsIndeterminate(t *testing.T) {
	t.Parallel()
	policy := grantPolicy(tailscale.Grant{
		Source:      []string{"tag:web"},
		Destination: []string{"ipset:broken"},
		IP:          []string{"tcp:80"},
	})
	policy.IPSets = map[string][]string{"ipset:broken": {"host:missing"}}

	got := evaluate(t, policy, "tag:web", "10.0.0.1:80", aclpolicy.ReachabilityOptions{})

	if got.Access != aclpolicy.AccessIndeterminate {
		t.Fatalf("Access = %q, want %q; evidence: %s", got.Access, aclpolicy.AccessIndeterminate, got.Evidence)
	}
	if got.Allowed != nil {
		t.Errorf("Allowed = %v, want nil; an indeterminate answer must not claim a boolean", *got.Allowed)
	}
	if !strings.Contains(got.Evidence, "ipset:broken") {
		t.Errorf("Evidence = %q, want it to name ipset:broken", got.Evidence)
	}
	if got.Rule == nil || got.Rule.Kind != aclpolicy.RuleGrant || got.Rule.Index != 0 {
		t.Errorf("Rule = %+v, want the gating grant 0", got.Rule)
	}
}

func TestUndefinedIPSetSelectorStillDenies(t *testing.T) {
	t.Parallel()
	policy := grantPolicy(tailscale.Grant{
		Source:      []string{"tag:web"},
		Destination: []string{"ipset:undefined"},
		IP:          []string{"tcp:80"},
	})

	got := evaluate(t, policy, "tag:web", "10.0.0.1:80", aclpolicy.ReachabilityOptions{})

	if got.Access != aclpolicy.AccessDeny {
		t.Errorf("Access = %q, want %q; evidence: %s", got.Access, aclpolicy.AccessDeny, got.Evidence)
	}
}

// A test suite over a trimmed set used to pass a deny of an address the
// control plane accepts, and could not express the accept at all.
func TestEvaluateTestsResolvesIPSetMemberForms(t *testing.T) {
	t.Parallel()
	policy := grantPolicy(tailscale.Grant{
		Source:      []string{"tag:web"},
		Destination: []string{"ipset:trimmed"},
		IP:          []string{"tcp:80"},
	})
	policy.IPSets = map[string][]string{"ipset:trimmed": {"add 10.0.0.0/8", "remove 10.1.0.0/16"}}
	policy.Tests = []tailscale.ACLTest{
		{Source: "tag:web", Accept: []string{"10.2.0.5:80"}},
		{Source: "tag:web", Deny: []string{"10.2.0.5:80"}},
	}

	report, err := aclpolicy.EvaluateTests(policy, aclpolicy.TestOptions{})
	if err != nil {
		t.Fatalf("EvaluateTests: %v", err)
	}
	if len(report.Assertions) != 2 {
		t.Fatalf("got %d assertions, want 2", len(report.Assertions))
	}
	if report.Assertions[0].Status != aclpolicy.AssertionPass {
		t.Errorf("accept 10.2.0.5:80 = %q, want %q: %s",
			report.Assertions[0].Status, aclpolicy.AssertionPass, report.Assertions[0].Evidence)
	}
	if report.Assertions[1].Status != aclpolicy.AssertionFail {
		t.Errorf("deny 10.2.0.5:80 = %q, want %q: %s",
			report.Assertions[1].Status, aclpolicy.AssertionFail, report.Assertions[1].Evidence)
	}
}
