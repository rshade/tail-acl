package aclpolicy_test

import (
	"reflect"
	"testing"

	tailscale "tailscale.com/client/tailscale/v2"

	"github.com/rshade/tail-acl/internal/aclpolicy"
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

// A flag-less add does not merge into a posture-qualified entry: a posture
// test is identified by its source AND its attributes, and an add carrying
// no attributes matches only entries with no srcPostureAttrs key or an empty
// one, so the add forks a plain entry with the modern spelling.
func TestAddAssertionsFlaglessAddDoesNotMergeIntoPostureQualifiedEntry(t *testing.T) {
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

// kpTestAttrs is the attribute set the posture-add tests share, as a function
// because the edit functions take ownership of the map they are given.
func kpTestAttrs() map[string]any {
	return map[string]any{"node:os": "linux", "ip:country": "KP"}
}

// An add carrying attributes writes a new entry whose srcPostureAttrs is the
// typed map.
func TestAddAssertionsWithPostureAttrsWritesNewEntry(t *testing.T) {
	t.Parallel()
	policy := &aclpolicy.Policy{Tests: []tailscale.ACLTest{}}
	_, err := aclpolicy.AddAssertions(
		policy, "alice@example.com", []string{"bbb:443", "nyc-svc:443"}, nil, kpTestAttrs(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(policy.Tests) != 1 {
		t.Fatalf("tests = %#v, want one new entry", policy.Tests)
	}
	created := policy.Tests[0]
	if !reflect.DeepEqual(created.SrcPostureAttrs, kpTestAttrs()) {
		t.Errorf("SrcPostureAttrs = %#v, want %#v", created.SrcPostureAttrs, kpTestAttrs())
	}
	if !reflect.DeepEqual(created.Deny, []string{"bbb:443", "nyc-svc:443"}) {
		t.Errorf("deny = %#v", created.Deny)
	}
}

// Repeating an add against the entry it created merges idempotently: the
// already-present assertion contributes no operation and the new one appends
// into the same entry.
func TestAddAssertionsWithPostureAttrsMergesIdempotently(t *testing.T) {
	t.Parallel()
	policy := &aclpolicy.Policy{Tests: []tailscale.ACLTest{
		{Source: "alice@example.com", Deny: []string{"bbb:443"}, SrcPostureAttrs: kpTestAttrs()},
	}}
	repeat, err := aclpolicy.AddAssertions(
		policy, "alice@example.com", []string{"bbb:443"}, []string{"nyc-svc:22"}, kpTestAttrs(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(policy.Tests) != 1 {
		t.Fatalf("tests = %#v, want the merge not to fork", policy.Tests)
	}
	if len(repeat.Operations) != 1 {
		t.Errorf("operations = %d, want only the new accept's append", len(repeat.Operations))
	}
	if !reflect.DeepEqual(policy.Tests[0].Accept, []string{"nyc-svc:22"}) {
		t.Errorf("accept = %#v", policy.Tests[0].Accept)
	}
	if !reflect.DeepEqual(repeat.AssertionIDs,
		[]string{"tests[0].deny[0]", "tests[0].accept[0]"}) {
		t.Errorf("assertion IDs = %#v", repeat.AssertionIDs)
	}
}

// A posture test is identified by source AND attributes: the same source
// with a different country forks a second entry.
func TestAddAssertionsWithDifferentPostureAttrsForks(t *testing.T) {
	t.Parallel()
	policy := &aclpolicy.Policy{Tests: []tailscale.ACLTest{
		{Source: "alice@example.com", Deny: []string{"bbb:443"}, SrcPostureAttrs: kpTestAttrs()},
	}}
	forkAttrs := map[string]any{"node:os": "linux", "ip:country": "IR"}
	fork, err := aclpolicy.AddAssertions(
		policy, "alice@example.com", []string{"bbb:443"}, nil, forkAttrs,
	)
	if err != nil {
		t.Fatal(err)
	}
	if fork.TestIndex != 1 || len(policy.Tests) != 2 {
		t.Fatalf("edit index = %d, tests = %#v, want a fork at index 1", fork.TestIndex, policy.Tests)
	}
	if !reflect.DeepEqual(policy.Tests[1].SrcPostureAttrs, forkAttrs) {
		t.Errorf("forked entry attrs = %#v, want %#v", policy.Tests[1].SrcPostureAttrs, forkAttrs)
	}
}

// The attribute match is deep-equal after typing: a JSON-decoded 5.0 and the
// flag-typed 5 are the same value, so the add merges rather than forks.
func TestAddAssertionsPostureAttrsDeepEqualAfterTyping(t *testing.T) {
	t.Parallel()
	typedPolicy := &aclpolicy.Policy{Tests: []tailscale.ACLTest{
		{
			Source:          "alice@example.com",
			Deny:            []string{"bbb:443"},
			SrcPostureAttrs: map[string]any{"custom:score": 5.0},
		},
	}}
	typedAttrs, err := aclpolicy.ParsePostureAttrs([]string{"custom:score=5"})
	if err != nil {
		t.Fatal(err)
	}
	merge, err := aclpolicy.AddAssertions(
		typedPolicy, "alice@example.com", nil, []string{"bbb:22"}, typedAttrs,
	)
	if err != nil {
		t.Fatal(err)
	}
	if merge.TestIndex != 0 || len(typedPolicy.Tests) != 1 {
		t.Errorf("edit index = %d, tests = %#v, want a merge not a fork",
			merge.TestIndex, typedPolicy.Tests)
	}
}

// A removal carrying attributes targets only the entry whose attribute map
// matches exactly, under the existing renumbering rules.
func TestRemoveAssertionsWithPostureAttrs(t *testing.T) {
	t.Parallel()
	newPolicy := func() *aclpolicy.Policy {
		return &aclpolicy.Policy{Tests: []tailscale.ACLTest{
			{
				Source:          "alice@example.com",
				Deny:            []string{"bbb:443"},
				SrcPostureAttrs: map[string]any{"ip:country": "KP"},
			},
			{
				Source:          "alice@example.com",
				Deny:            []string{"bbb:443"},
				SrcPostureAttrs: map[string]any{"ip:country": "IR"},
			},
		}}
	}

	t.Run("exact match removes only the targeted entry", func(t *testing.T) {
		t.Parallel()
		policy := newPolicy()
		edit, err := aclpolicy.RemoveAssertions(
			policy, "alice@example.com", []string{"bbb:443"}, nil,
			map[string]any{"ip:country": "KP"},
		)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(edit.AssertionIDs, []string{"tests[0].deny[0]"}) {
			t.Errorf("assertion IDs = %#v", edit.AssertionIDs)
		}
		if len(policy.Tests) != 1 ||
			!reflect.DeepEqual(policy.Tests[0].SrcPostureAttrs, map[string]any{"ip:country": "IR"}) {
			t.Errorf("tests = %#v, want only the IR entry left", policy.Tests)
		}
	})

	t.Run("no exact match changes nothing", func(t *testing.T) {
		t.Parallel()
		policy := newPolicy()
		edit, err := aclpolicy.RemoveAssertions(
			policy, "alice@example.com", []string{"bbb:443"}, nil,
			map[string]any{"ip:country": "RU"},
		)
		if err != nil {
			t.Fatal(err)
		}
		if edit.Changed() || len(policy.Tests) != 2 {
			t.Errorf("edit = %#v, tests = %#v, want no changes", edit, policy.Tests)
		}
	})

	t.Run("a flag-less removal skips both posture entries", func(t *testing.T) {
		t.Parallel()
		policy := newPolicy()
		edit, err := aclpolicy.RemoveAssertions(
			policy, "alice@example.com", []string{"bbb:443"}, nil, nil,
		)
		if err != nil {
			t.Fatal(err)
		}
		if edit.Changed() || len(policy.Tests) != 2 {
			t.Errorf("edit = %#v, tests = %#v, want no changes", edit, policy.Tests)
		}
	})
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
		nil,
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

// The empty-{} decision: an entry spelling an empty srcPostureAttrs object is
// treated as attribute-less by flag-less edits — a flag-less removal targets
// it and a flag-less add merges into it — because the runner treats its map
// as a complete all-unset set and the flags cannot express an empty set. An
// add carrying attributes still forks past it.
func TestEditsMatchEntryWithEmptyPostureAttrs(t *testing.T) {
	t.Parallel()

	t.Run("flag-less removal targets the entry", func(t *testing.T) {
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
	})

	t.Run("flag-less add merges into the entry", func(t *testing.T) {
		t.Parallel()
		policy := &aclpolicy.Policy{Tests: []tailscale.ACLTest{
			{
				Source:          "alice@example.com",
				Deny:            []string{"tag:db:5432"},
				SrcPostureAttrs: map[string]any{},
			},
		}}
		edit, err := aclpolicy.AddAssertion(
			policy, "alice@example.com", aclpolicy.TestDeny, "tag:cache:6379",
		)
		if err != nil {
			t.Fatal(err)
		}
		if edit.TestIndex != 0 || len(policy.Tests) != 1 {
			t.Errorf("edit = %#v, tests = %#v, want a merge not a fork", edit, policy.Tests)
		}
	})

	t.Run("an add carrying attributes forks past the entry", func(t *testing.T) {
		t.Parallel()
		policy := &aclpolicy.Policy{Tests: []tailscale.ACLTest{
			{
				Source:          "alice@example.com",
				Deny:            []string{"tag:db:5432"},
				SrcPostureAttrs: map[string]any{},
			},
		}}
		edit, err := aclpolicy.AddAssertions(
			policy, "alice@example.com", []string{"tag:cache:6379"}, nil,
			map[string]any{"ip:country": "KP"},
		)
		if err != nil {
			t.Fatal(err)
		}
		if edit.TestIndex != 1 || len(policy.Tests) != 2 {
			t.Errorf("edit = %#v, tests = %#v, want a fork at index 1", edit, policy.Tests)
		}
	})
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
