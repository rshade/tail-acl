package aclpolicy_test

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/rshade/tailscale-utils/tail-acl/internal/aclpolicy"
)

func TestDefinitionValidation(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name string
		got  func() error
	}{
		{"group name requires prefix", func() error {
			_, err := aclpolicy.NormalizeGroupName("eng")
			return err
		}},
		{"empty group member", func() error {
			return aclpolicy.ValidateGroupMember(" ")
		}},
		{"group member rejects cidr", func() error {
			return aclpolicy.ValidateGroupMember("10.0.0.0/8")
		}},
		{"ipset name requires prefix", func() error {
			_, err := aclpolicy.NormalizeIPSetName("office")
			return err
		}},
		{"ipset member requires cidr", func() error {
			_, err := aclpolicy.NormalizeIPSetCIDR("10.0.0.1")
			return err
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if err := test.got(); err == nil {
				t.Error("validation succeeded, want error")
			}
		})
	}

	if got, err := aclpolicy.NormalizeIPSetCIDR("10.2.3.4/8"); err != nil || got != "10.0.0.0/8" {
		t.Errorf("NormalizeIPSetCIDR = %q, %v; want 10.0.0.0/8", got, err)
	}
}

//nolint:gocognit // this integration-shaped test checks both map kinds and their byte-preserving write path.
func TestAddDefinitionMergesAndDeduplicates(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.hujson")
	original := `{
		// retain the policy comment
		"groups": {
			// retain the group comment
			"group:eng": ["alice@example.com"],
		},
		"ipsets": {"ipset:office": ["10.0.0.0/8"]},
	}`
	if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	policy, err := aclpolicy.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	groupEdit, err := aclpolicy.AddDefinition(policy, aclpolicy.DefinitionGroup, "group:eng",
		[]string{"alice@example.com", "bob@example.com", "bob@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if len(groupEdit.Operations) != 1 || !groupEdit.Existed {
		t.Fatalf("group edit = %#v, want one merge operation on existing definition", groupEdit)
	}
	if err = aclpolicy.WritePatch(path, groupEdit.Operations...); err != nil {
		t.Fatal(err)
	}

	policy, err = aclpolicy.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	ipsetEdit, err := aclpolicy.AddDefinition(policy, aclpolicy.DefinitionIPSet, "ipset:office",
		[]string{"10.1.2.3/8", "192.168.0.0/16"})
	if err != nil {
		t.Fatal(err)
	}
	if err = aclpolicy.WritePatch(path, ipsetEdit.Operations...); err != nil {
		t.Fatal(err)
	}

	policy, err = aclpolicy.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(policy.Groups["group:eng"], []string{"alice@example.com", "bob@example.com"}) {
		t.Errorf("group members = %v", policy.Groups["group:eng"])
	}
	if !slices.Equal(policy.IPSets["ipset:office"], []string{"10.0.0.0/8", "192.168.0.0/16"}) {
		t.Errorf("ipset members = %v", policy.IPSets["ipset:office"])
	}
	raw, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatal(readErr)
	}
	for _, comment := range []string{"// retain the policy comment", "// retain the group comment"} {
		if !strings.Contains(string(raw), comment) {
			t.Errorf("edit lost %q:\n%s", comment, raw)
		}
	}

	policy, err = aclpolicy.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	noChange, err := aclpolicy.AddDefinition(policy, aclpolicy.DefinitionIPSet, "ipset:office",
		[]string{"10.0.0.0/8", "192.168.0.0/16"})
	if err != nil {
		t.Fatal(err)
	}
	if noChange.Changed() {
		t.Error("re-adding ipset members produced an edit")
	}
	legacy := mustLoad(t, `{"ipsets": {"ipset:legacy": ["10.1.2.3/8"]}}`)
	legacyEdit, err := aclpolicy.AddDefinition(
		legacy, aclpolicy.DefinitionIPSet, "ipset:legacy", []string{"10.0.0.0/8"},
	)
	if err != nil {
		t.Fatal(err)
	}
	if legacyEdit.Changed() {
		t.Error("semantically equivalent CIDR produced a duplicate edit")
	}
}

func TestRemoveDefinitionRefusesReferencesAndAllowsUnused(t *testing.T) {
	t.Parallel()
	policy := mustLoad(t, `{
		"groups": {
			"group:eng": ["alice@example.com"],
			"group:unused": ["bob@example.com"],
		},
		"ipsets": {"ipset:office": ["10.0.0.0/8"]},
		"grants": [{"src": ["group:eng"], "dst": ["ipset:office"], "ip": ["tcp:443"]}],
	}`)
	if _, err := aclpolicy.RemoveDefinition(policy, aclpolicy.DefinitionGroup, "group:eng", false); err == nil {
		t.Fatal("referenced group removal succeeded, want refusal")
	} else if !strings.Contains(err.Error(), "grants[0].src[0]") {
		t.Errorf("refusal = %q, want referencing site", err)
	}
	if _, err := aclpolicy.RemoveDefinition(policy, aclpolicy.DefinitionIPSet, "ipset:office", false); err == nil {
		t.Fatal("referenced ipset removal succeeded, want refusal")
	} else if !strings.Contains(err.Error(), "grants[0].dst[0]") {
		t.Errorf("refusal = %q, want referencing site", err)
	}
	edit, err := aclpolicy.RemoveDefinition(policy, aclpolicy.DefinitionGroup, "group:unused", false)
	if err != nil || !edit.Changed() {
		t.Fatalf("unused group removal = %#v, %v; want an edit", edit, err)
	}
	forced, err := aclpolicy.RemoveDefinition(policy, aclpolicy.DefinitionGroup, "group:eng", true)
	if err != nil || !forced.Changed() {
		t.Fatalf("forced group removal = %#v, %v; want an edit", forced, err)
	}
}

// TestRemoveDefinitionSeesNodeAttrAndViaReferences covers the two selector
// fields the reference walk once skipped. Each is the only reference to its
// definition, so a walk that misses the field removes a live definition
// without ever offering --force.
func TestRemoveDefinitionSeesNodeAttrAndViaReferences(t *testing.T) {
	t.Parallel()
	policy := mustLoad(t, `{
		"groups": {"group:eng": ["alice@example.com"]},
		"ipsets": {"ipset:office": ["10.0.0.0/8"]},
		"nodeAttrs": [{"target": ["group:eng"], "attr": ["funnel"]}],
		"grants": [{
			"src": ["autogroup:member"], "dst": ["tag:web"],
			"ip": ["tcp:443"], "via": ["ipset:office"],
		}],
	}`)
	for _, test := range []struct {
		name string
		kind aclpolicy.DefinitionKind
		want string
	}{
		{"group:eng", aclpolicy.DefinitionGroup, "nodeAttrs[0].target[0]"},
		{"ipset:office", aclpolicy.DefinitionIPSet, "grants[0].via[0]"},
	} {
		t.Run(test.want, func(t *testing.T) {
			t.Parallel()
			_, err := aclpolicy.RemoveDefinition(policy, test.kind, test.name, false)
			if err == nil {
				t.Fatalf("%s was removable without --force", test.name)
			}
			if !strings.Contains(err.Error(), test.want) {
				t.Errorf("refusal = %q, want site %s", err, test.want)
			}
		})
	}
}

func TestRemoveDefinitionSeesNodeAttrAppConnectorReferences(t *testing.T) {
	t.Parallel()
	policy := mustLoad(t, `{
		"groups": {"group:eng": ["alice@example.com"]},
		"ipsets": {"ipset:office": ["10.0.0.0/8"]},
		"nodeAttrs": [{
			"target": ["*"],
			"app": {"tailscale.com/app-connectors": [{
				"connectors": ["group:eng", "ipset:office"]
			}]}
		}]
	}`)
	for _, test := range []struct {
		name string
		kind aclpolicy.DefinitionKind
		want string
	}{
		{"group:eng", aclpolicy.DefinitionGroup, `nodeAttrs[0].app["tailscale.com/app-connectors"][0].connectors[0]`},
		{"ipset:office", aclpolicy.DefinitionIPSet, `nodeAttrs[0].app["tailscale.com/app-connectors"][0].connectors[1]`},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			_, err := aclpolicy.RemoveDefinition(policy, test.kind, test.name, false)
			if err == nil {
				t.Fatalf("%s was removable without --force", test.name)
			}
			if !strings.Contains(err.Error(), test.want) {
				t.Errorf("refusal = %q, want site %s", err, test.want)
			}
		})
	}
}

// TestAddDefinitionPatchesNullValuedDefinition covers a definition present in
// the map with a null value. It decodes to a nil slice, so an append-into-array
// patch cannot apply to it and the command died inside hujson with an internal
// pointer error. AddRouteApprovers has always handled the same shape.
func TestAddDefinitionPatchesNullValuedDefinition(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		kind    aclpolicy.DefinitionKind
		policy  string
		name    string
		member  string
		members func(*aclpolicy.Policy, string) []string
	}{
		{
			aclpolicy.DefinitionGroup, `{"groups": {"group:eng": null}}`,
			"group:eng", "alice@example.com",
			func(p *aclpolicy.Policy, n string) []string { return p.Groups[n] },
		},
		{
			aclpolicy.DefinitionIPSet, `{"ipsets": {"ipset:office": null}}`,
			"ipset:office", "10.0.0.0/8",
			func(p *aclpolicy.Policy, n string) []string { return p.IPSets[n] },
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "acl.hujson")
			if err := os.WriteFile(path, []byte(test.policy), 0o600); err != nil {
				t.Fatal(err)
			}
			edit, err := aclpolicy.AddDefinition(
				mustLoadFile(t, path), test.kind, test.name, []string{test.member},
			)
			if err != nil {
				t.Fatal(err)
			}
			if err = aclpolicy.WritePatch(path, edit.Operations...); err != nil {
				t.Fatalf("patching a null-valued %s failed: %v", test.kind, err)
			}
			if got := test.members(mustLoadFile(t, path), test.name); !slices.Equal(got, []string{test.member}) {
				t.Errorf("members = %v, want [%s]", got, test.member)
			}
		})
	}
}

func mustLoadFile(t *testing.T, path string) *aclpolicy.Policy {
	t.Helper()
	policy, err := aclpolicy.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	return policy
}
