package aclpolicy_test

import (
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	tailscale "tailscale.com/client/tailscale/v2"

	"github.com/rshade/tailscale-utils/tail-acl/internal/aclpolicy"
)

const externalTailnetFixture = `{
	"groups": {
		"group:eng": ["alice@example.com"],
	},
	"grants": [
		{"src": ["group:eng"], "dst": ["autogroup:self"], "ip": ["*"]},
	],
	"externalTailnets": {
		// Partner can name engineering
		"partner": {
			"externalID": "tn-123",
			"allowExternalReferencesTo": ["group:eng"],
		},
	},
}
`

func TestLoadReadsExternalTailnets(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.hujson")
	writeFile(t, path, externalTailnetFixture)

	policy, err := aclpolicy.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	got := policy.ExternalTailnets["partner"]
	if got.ExternalID != "tn-123" {
		t.Errorf("ExternalID = %q, want tn-123", got.ExternalID)
	}
	if !slices.Equal(got.AllowExternalReferencesTo, []string{"group:eng"}) {
		t.Errorf("AllowExternalReferencesTo = %#v", got.AllowExternalReferencesTo)
	}
}

func TestUnrelatedPatchPreservesExternalTailnetComment(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.hujson")
	writeFile(t, path, externalTailnetFixture)

	grant := tailscale.Grant{
		Source:      []string{"group:eng"},
		Destination: []string{"autogroup:internet"},
		IP:          []string{"*"},
	}
	if err := aclpolicy.WritePatch(path, aclpolicy.PatchAdd(grant, "grants", "-")); err != nil {
		t.Fatal(err)
	}

	after := readFile(t, path)
	// hujson realigns value columns when it rewrites the document. The comment
	// itself, including its indentation, must stay byte-for-byte.
	const commentLine = "\t\t// Partner can name engineering\n"
	if strings.Count(after, commentLine) != 1 {
		t.Errorf("comment line count = %d, want 1:\n%s", strings.Count(after, commentLine), after)
	}
	policy, err := aclpolicy.Load(path)
	if err != nil {
		t.Fatalf("patched policy does not load: %v\n%s", err, after)
	}
	if policy.ExternalTailnets["partner"].ExternalID != "tn-123" {
		t.Errorf("ExternalID after patch = %q", policy.ExternalTailnets["partner"].ExternalID)
	}
}

func TestEvaluateLintCountsExternalTailnetReferences(t *testing.T) {
	t.Parallel()
	policy := &tailscale.ACL{
		Groups: map[string][]string{"group:eng": {"alice@example.com"}},
		TagOwners: map[string][]string{
			"tag:partner-device": {"autogroup:admin"},
		},
		ExternalTailnets: map[string]tailscale.ExternalTailnet{
			"partner": {AllowExternalReferencesTo: []string{"group:eng", "tag:partner-device"}},
		},
	}
	report, err := aclpolicy.EvaluateLint(policy, aclpolicy.LintOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if unused := findingsByID(report, aclpolicy.LintUnusedGroup); len(unused) != 0 {
		t.Errorf("unused-group = %#v, want none", unused)
	}
	if unused := findingsByID(report, aclpolicy.LintUnusedTag); len(unused) != 0 {
		t.Errorf("unused-tag = %#v, want none", unused)
	}
}

func TestRemoveDefinitionRefusesExternalTailnetReference(t *testing.T) {
	t.Parallel()
	policy := &aclpolicy.Policy{
		Groups: map[string][]string{"group:eng": {"alice@example.com"}},
		ExternalTailnets: map[string]tailscale.ExternalTailnet{
			"partner": {AllowExternalReferencesTo: []string{"group:eng"}},
		},
	}
	_, err := aclpolicy.RemoveDefinition(policy, aclpolicy.DefinitionGroup, "group:eng", false)
	var referenced *aclpolicy.DefinitionReferenceError
	if !errors.As(err, &referenced) {
		t.Fatalf("RemoveDefinition error = %v, want DefinitionReferenceError", err)
	}
	want := "externalTailnets[partner].allowExternalReferencesTo[0]"
	if !slices.Contains(referenced.References, want) {
		t.Errorf("references = %v, want %s", referenced.References, want)
	}
	if _, err = aclpolicy.RemoveDefinition(policy, aclpolicy.DefinitionGroup, "group:eng", true); err != nil {
		t.Fatalf("forced remove: %v", err)
	}
}
