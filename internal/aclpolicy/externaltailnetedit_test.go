package aclpolicy_test

import (
	"errors"
	"slices"
	"testing"

	tailscale "tailscale.com/client/tailscale/v2"

	"github.com/rshade/tail-acl/internal/aclpolicy"
)

func TestAddExternalTailnetIsIdempotent(t *testing.T) {
	t.Parallel()
	policy := &aclpolicy.Policy{}
	spec := aclpolicy.ExternalTailnetSpec{Alias: "partner", ExternalID: "tn-123"}
	first, err := aclpolicy.AddExternalTailnet(policy, spec)
	if err != nil {
		t.Fatal(err)
	}
	if !first.Changed() || first.Existed {
		t.Fatalf("first edit = %+v", first)
	}
	policy.ExternalTailnets = map[string]tailscale.ExternalTailnet{
		"partner": {ExternalID: "tn-123"},
	}
	second, err := aclpolicy.AddExternalTailnet(policy, spec)
	if err != nil {
		t.Fatal(err)
	}
	if second.Changed() || !second.Existed {
		t.Fatalf("second edit = %+v, want no-op", second)
	}
}

func TestAddExternalTailnetReplacesADifferentID(t *testing.T) {
	t.Parallel()
	policy := &aclpolicy.Policy{}
	policy.ExternalTailnets = map[string]tailscale.ExternalTailnet{
		"partner": {ExternalID: "tn-old"},
	}
	edit, err := aclpolicy.AddExternalTailnet(policy, aclpolicy.ExternalTailnetSpec{
		Alias: "partner", ExternalID: "tn-new", AllowIncomingConnections: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !edit.Changed() || !edit.Existed {
		t.Fatalf("edit = %+v", edit)
	}
}

func TestRemoveExternalTailnetRefusesGrantReference(t *testing.T) {
	t.Parallel()
	policy := partnerGrantPolicy()
	_, err := aclpolicy.RemoveExternalTailnet(policy, "partner", false)
	var refused *aclpolicy.ExternalTailnetReferenceError
	if !errors.As(err, &refused) {
		t.Fatalf("error = %v, want reference error", err)
	}
	if !slices.Contains(refused.References, "grants[0].src[0]") {
		t.Errorf("references = %#v", refused.References)
	}
	forced, err := aclpolicy.RemoveExternalTailnet(policy, "partner", true)
	if err != nil || !forced.Changed() {
		t.Fatalf("forced = %+v, err = %v", forced, err)
	}
}

func TestRemoveExternalTailnetRefusesLintSelectorPositions(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name   string
		policy *aclpolicy.Policy
		want   string
	}{
		{
			name: "acl users and ports",
			policy: policyWith(func(policy *aclpolicy.Policy) {
				policy.ACLs = []tailscale.ACLEntry{{
					Users: []string{"group://partner/eng"},
					Ports: []string{"tag://partner/web:22"},
				}}
			}),
			want: "acls[0].users[0]",
		},
		{
			name: "acl port on the same entry",
			policy: policyWith(func(policy *aclpolicy.Policy) {
				policy.ACLs = []tailscale.ACLEntry{{
					Ports: []string{"tag://partner/web:22"},
				}}
			}),
			want: "acls[0].ports[0]",
		},
		{
			name: "ssh recorder",
			policy: policyWith(func(policy *aclpolicy.Policy) {
				var rule aclpolicy.SSHRule
				rule.Recorder = []string{"tag://partner/recorder"}
				policy.SSH = []aclpolicy.SSHRule{rule}
			}),
			want: "ssh[0].recorder[0]",
		},
		{
			name: "auto approver service",
			policy: policyWith(func(policy *aclpolicy.Policy) {
				policy.AutoApprovers = &tailscale.ACLAutoApprovers{
					Services: map[string][]string{"svc:web": {"group://partner/eng"}},
				}
			}),
			want: "autoApprovers.services[svc:web][0]",
		},
		{
			name: "legacy test user",
			policy: policyWith(func(policy *aclpolicy.Policy) {
				policy.Tests = []tailscale.ACLTest{{User: "group://partner/eng"}}
			}),
			want: "tests[0].user",
		},
		{
			name: "legacy test allow",
			policy: policyWith(func(policy *aclpolicy.Policy) {
				policy.Tests = []tailscale.ACLTest{{Allow: []string{"tag://partner/web:22"}}}
			}),
			want: "tests[0].allow[0]",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			_, err := aclpolicy.RemoveExternalTailnet(test.policy, "partner", false)
			var refused *aclpolicy.ExternalTailnetReferenceError
			if !errors.As(err, &refused) {
				t.Fatalf("error = %v, want reference error", err)
			}
			if !slices.Contains(refused.References, test.want) {
				t.Errorf("references = %#v, want %s", refused.References, test.want)
			}
		})
	}
}

func TestRemoveExternalTailnetIgnoresLegacyACLFieldsWhenModernFieldsAreSet(t *testing.T) {
	t.Parallel()
	policy := policyWith(func(policy *aclpolicy.Policy) {
		policy.ACLs = []tailscale.ACLEntry{{
			Source:      []string{"autogroup:member"},
			Destination: []string{"autogroup:self"},
			Users:       []string{"group://partner/eng"},
			Ports:       []string{"tag://partner/web:22"},
		}}
	})
	edit, err := aclpolicy.RemoveExternalTailnet(policy, "partner", false)
	if err != nil || !edit.Changed() {
		t.Fatalf("edit = %+v, err = %v", edit, err)
	}
}

func TestRemoveMissingExternalTailnetIsANoOp(t *testing.T) {
	t.Parallel()
	edit, err := aclpolicy.RemoveExternalTailnet(&aclpolicy.Policy{}, "partner", false)
	if err != nil || edit.Changed() {
		t.Fatalf("edit = %+v, err = %v", edit, err)
	}
}

func TestListExternalTailnetsSortsAliases(t *testing.T) {
	t.Parallel()
	policy := &aclpolicy.Policy{}
	policy.ExternalTailnets = map[string]tailscale.ExternalTailnet{
		"zeta":  {ExternalID: "tn-z"},
		"alpha": {ExternalID: "tn-a", AllowIncomingConnections: true},
	}
	entries := aclpolicy.ListExternalTailnets(policy)
	if len(entries) != 2 || entries[0].Alias != "alpha" || entries[1].Alias != "zeta" {
		t.Fatalf("entries = %+v", entries)
	}
	if !entries[0].AllowIncomingConnections || entries[1].AllowIncomingConnections {
		t.Errorf("incoming flags = %+v", entries)
	}
}

func policyWith(apply func(*aclpolicy.Policy)) *aclpolicy.Policy {
	policy := &aclpolicy.Policy{}
	policy.ExternalTailnets = map[string]tailscale.ExternalTailnet{
		"partner": {ExternalID: "tn-123"},
	}
	apply(policy)
	return policy
}

func partnerGrantPolicy() *aclpolicy.Policy {
	return policyWith(func(policy *aclpolicy.Policy) {
		policy.Grants = []tailscale.Grant{{
			Source:      []string{"group://partner/eng"},
			Destination: []string{"autogroup:self"},
			IP:          []string{"*"},
		}}
	})
}
