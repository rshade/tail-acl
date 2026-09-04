package aclpolicy_test

import (
	"reflect"
	"testing"

	tailscale "tailscale.com/client/tailscale/v2"

	"github.com/rshade/tailscale-utils/tail-acl/internal/aclpolicy"
)

func TestAddAssertionsMergesBySemanticAssertion(t *testing.T) {
	t.Parallel()
	policy := &aclpolicy.Policy{Tests: []tailscale.ACLTest{
		{Source: "alice@example.com", Deny: []string{"tag:db:5432", "tag:cache:6379"}},
	}}

	edit, err := aclpolicy.AddAssertions(
		policy,
		" alice@example.com ",
		[]string{" tag:db:5432 ", "tag:queue:5672"},
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	if edit.TestIndex != 0 || !reflect.DeepEqual(edit.AssertionIDs, []string{
		"tests[0].deny[0]", "tests[0].deny[2]",
	}) {
		t.Errorf("edit = %#v", edit)
	}
	if len(edit.Operations) != 1 {
		t.Fatalf("operations = %d, want 1", len(edit.Operations))
	}
	want := []string{"tag:db:5432", "tag:cache:6379", "tag:queue:5672"}
	if !reflect.DeepEqual(policy.Tests[0].Deny, want) {
		t.Errorf("deny = %#v, want %#v", policy.Tests[0].Deny, want)
	}
}

func TestAddAssertionsSkipsPostureQualifiedEntryAndUsesModernSpelling(t *testing.T) {
	t.Parallel()
	policy := &aclpolicy.Policy{Tests: []tailscale.ACLTest{
		{
			Source:          "alice@example.com",
			Accept:          []string{"tag:old:443"},
			SrcPostureAttrs: map[string]any{"node:os": "linux"},
		},
	}}

	edit, err := aclpolicy.AddAssertion(
		policy, "alice@example.com", aclpolicy.TestAccept, "tag:web:443",
	)
	if err != nil {
		t.Fatal(err)
	}
	if edit.TestIndex != 1 || len(policy.Tests) != 2 {
		t.Fatalf("edit index = %d, tests = %#v", edit.TestIndex, policy.Tests)
	}
	if policy.Tests[1].Source != "alice@example.com" ||
		!reflect.DeepEqual(policy.Tests[1].Accept, []string{"tag:web:443"}) ||
		policy.Tests[1].Allow != nil || policy.Tests[1].User != "" {
		t.Errorf("new test = %#v", policy.Tests[1])
	}
}

func TestRemoveAssertionsRemovesDuplicatesAndPrunesEntry(t *testing.T) {
	t.Parallel()
	policy := &aclpolicy.Policy{Tests: []tailscale.ACLTest{
		{
			User:  "alice@example.com",
			Allow: []string{"tag:web:443", "tag:web:443"},
			Deny:  []string{"tag:db:5432"},
		},
		{Source: "bob@example.com", Deny: []string{"tag:db:5432"}},
	}}

	edit, err := aclpolicy.RemoveAssertions(
		policy,
		"alice@example.com",
		[]string{"tag:db:5432"},
		[]string{"tag:web:443"},
	)
	if err != nil {
		t.Fatal(err)
	}
	wantIDs := []string{
		"tests[0].accept[0]", "tests[0].accept[1]", "tests[0].deny[0]",
	}
	if !reflect.DeepEqual(edit.AssertionIDs, wantIDs) {
		t.Errorf("assertion IDs = %#v, want %#v", edit.AssertionIDs, wantIDs)
	}
	if len(edit.Operations) != 1 {
		t.Errorf("operations = %d, want one entry removal", len(edit.Operations))
	}
	if len(policy.Tests) != 1 || policy.Tests[0].Source != "bob@example.com" {
		t.Errorf("tests = %#v", policy.Tests)
	}
}

// An entry may spell an empty accept beside a populated legacy allow. Appending
// to accept there would populate both members, which normalizeTest rejects for
// the whole policy — so an edit must not be able to make a runnable policy
// unrunnable.
func TestAddAssertionsAppendsToTheFieldTheRunnerReads(t *testing.T) {
	t.Parallel()
	policy := &aclpolicy.Policy{Tests: []tailscale.ACLTest{
		{Source: "alice@example.com", Accept: []string{}, Allow: []string{"tag:web:443"}},
	}}

	if _, err := aclpolicy.AddAssertion(
		policy, "alice@example.com", aclpolicy.TestAccept, "tag:api:8443",
	); err != nil {
		t.Fatal(err)
	}
	want := []string{"tag:web:443", "tag:api:8443"}
	if !reflect.DeepEqual(policy.Tests[0].Allow, want) || len(policy.Tests[0].Accept) != 0 {
		t.Errorf("accept = %#v, allow = %#v, want allow %#v",
			policy.Tests[0].Accept, policy.Tests[0].Allow, want)
	}
	if _, err := aclpolicy.EvaluateTests(&policy.ACL, aclpolicy.TestOptions{}); err != nil {
		t.Errorf("policy is no longer runnable after an add: %v", err)
	}
}

func TestRemoveAssertionsMatchesTheFieldTheRunnerReads(t *testing.T) {
	t.Parallel()
	policy := &aclpolicy.Policy{Tests: []tailscale.ACLTest{
		{Source: "alice@example.com", Accept: []string{}, Allow: []string{"tag:web:443"}},
	}}

	edit, err := aclpolicy.RemoveAssertion(
		policy, "alice@example.com", aclpolicy.TestAccept, "tag:web:443",
	)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(edit.AssertionIDs, []string{"tests[0].accept[0]"}) {
		t.Errorf("assertion IDs = %#v", edit.AssertionIDs)
	}
	if len(policy.Tests) != 0 {
		t.Errorf("tests = %#v, want the emptied entry pruned", policy.Tests)
	}
}

// EvaluateTests refuses an entry only once it carries a posture attribute, so an
// empty srcPostureAttrs object still runs and must stay editable.
func TestEditsMatchEntryWithEmptyPostureAttrs(t *testing.T) {
	t.Parallel()
	policy := &aclpolicy.Policy{Tests: []tailscale.ACLTest{
		{
			Source:          "alice@example.com",
			Deny:            []string{"tag:db:5432"},
			SrcPostureAttrs: map[string]any{},
		},
	}}

	if _, err := aclpolicy.EvaluateTests(&policy.ACL, aclpolicy.TestOptions{}); err != nil {
		t.Fatalf("runner rejects an empty srcPostureAttrs entry: %v", err)
	}
	edit, err := aclpolicy.RemoveAssertion(
		policy, "alice@example.com", aclpolicy.TestDeny, "tag:db:5432",
	)
	if err != nil {
		t.Fatal(err)
	}
	if !edit.Changed() || len(policy.Tests) != 0 {
		t.Errorf("edit = %#v, tests = %#v", edit, policy.Tests)
	}
}

func TestValidateTestDestinationUsesRunnerSyntax(t *testing.T) {
	t.Parallel()
	for _, valid := range []string{"tag:web:443", "host.example.com:1", "[2001:db8::1]:65535"} {
		if err := aclpolicy.ValidateTestDestination(valid); err != nil {
			t.Errorf("ValidateTestDestination(%q) = %v", valid, err)
		}
	}
	for _, invalid := range []string{"", "tag:web", "tag:web:*", "2001:db8::1:443", "tag:web:65536"} {
		if err := aclpolicy.ValidateTestDestination(invalid); err == nil {
			t.Errorf("ValidateTestDestination(%q) unexpectedly succeeded", invalid)
		}
	}
}
