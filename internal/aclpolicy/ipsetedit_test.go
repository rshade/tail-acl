package aclpolicy_test

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/rshade/tail-acl/internal/aclpolicy"
	"github.com/rshade/tail-acl/pkg/policycore"
)

const ipsetMemberPolicy = `{
	"hosts": {"gw": "10.9.0.1"},
	"ipsets": {
		"ipset:base": ["10.0.0.0/8"],
		"ipset:x": ["192.168.0.0/16"],
	},
}`

func members(values ...string) []aclpolicy.IPSetMemberSpec {
	specs := make([]aclpolicy.IPSetMemberSpec, 0, len(values))
	for _, value := range values {
		specs = append(specs, aclpolicy.IPSetMemberSpec{Value: value})
	}
	return specs
}

func patchedIPSet(t *testing.T, policyText, name string, specs []aclpolicy.IPSetMemberSpec) []string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "acl.hujson")
	if err := os.WriteFile(path, []byte(policyText), 0o600); err != nil {
		t.Fatal(err)
	}
	edit, err := aclpolicy.AddIPSetMembers(mustLoadFile(t, path), name, specs)
	if err != nil {
		t.Fatalf("AddIPSetMembers(%s, %v) = %v", name, specs, err)
	}
	if err = aclpolicy.WritePatch(path, edit.Operations...); err != nil {
		t.Fatal(err)
	}
	return mustLoadFile(t, path).IPSets[name]
}

func TestAddIPSetMembersAcceptsEveryForm(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name   string
		member string
		want   string
	}{
		{"cidr is masked", "10.1.2.3/8", "10.0.0.0/8"},
		{"bare address", "10.0.0.1", "10.0.0.1"},
		{"range", "10.0.0.1-10.0.0.9", "10.0.0.1-10.0.0.9"},
		{"host alias", "host:gw", "host:gw"},
		{"nested ipset", "ipset:base", "ipset:base"},
		{"add operation", "add  ipset:base", "add ipset:base"},
		{"add range", "add 10.0.0.1-10.0.0.9", "add 10.0.0.1-10.0.0.9"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got := patchedIPSet(t, ipsetMemberPolicy, "ipset:x", members(test.member))
			if want := []string{"192.168.0.0/16", test.want}; !slices.Equal(got, want) {
				t.Errorf("ipset:x = %q; want %q", got, want)
			}
		})
	}
}

func TestAddIPSetMembersAppendsInArgumentOrder(t *testing.T) {
	t.Parallel()
	t.Run("member and cidr flags interleave", func(t *testing.T) {
		t.Parallel()
		got := patchedIPSet(t, ipsetMemberPolicy, "ipset:new", []aclpolicy.IPSetMemberSpec{
			{Value: "add ipset:base"}, {Value: "10.5.1.0/16", CIDROnly: true}, {Value: "add host:gw"},
		})
		if want := []string{"add ipset:base", "10.5.0.0/16", "add host:gw"}; !slices.Equal(got, want) {
			t.Errorf("ipset:new = %q; want %q", got, want)
		}
	})
	t.Run("all-explicit set with a remove", func(t *testing.T) {
		t.Parallel()
		got := patchedIPSet(t, ipsetMemberPolicy, "ipset:new",
			members("add ipset:base", "add host:gw", "add 10.0.0.0/8", "remove 10.1.0.0/16"))
		want := []string{"add ipset:base", "add host:gw", "add 10.0.0.0/8", "remove 10.1.0.0/16"}
		if !slices.Equal(got, want) {
			t.Errorf("ipset:new = %q; want %q", got, want)
		}
	})
}

func TestAddIPSetMembersRejections(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name    string
		policy  string
		set     string
		members []aclpolicy.IPSetMemberSpec
		want    string
	}{
		{
			"missing host alias", ipsetMemberPolicy, "ipset:x",
			members("host:nope"), `ipset member "host:nope" names host alias "nope", which is not defined in hosts`,
		},
		{
			"missing ipset", ipsetMemberPolicy, "ipset:x",
			members("add ipset:nope"), `ipset member "add ipset:nope" references ipset:nope, which is not defined in ipsets`,
		},
		{
			"self reference", ipsetMemberPolicy, "ipset:x",
			members("ipset:x"), `ipset member "ipset:x" references ipset:x itself`,
		},
		{
			"cycle through existing definitions",
			`{"ipsets": {"ipset:x": [], "ipset:a": ["add ipset:b"], "ipset:b": ["ipset:x"]}}`, "ipset:x",
			members("ipset:a"), `ipset member "ipset:a" creates a cycle: ipset:x -> ipset:a -> ipset:b -> ipset:x`,
		},
		{
			"implicit member beside a remove", ipsetMemberPolicy, "ipset:new",
			members("ipset:base", "host:gw", "add 10.0.0.0/8", "remove 10.1.0.0/16"),
			`ipset member "ipset:base" needs an explicit operation because the set contains "remove 10.1.0.0/16": ` +
				`write it as "add ipset:base"`,
		},
		{
			"existing implicit member beside a new remove", ipsetMemberPolicy, "ipset:x",
			members("remove 192.168.1.0/24"),
			`ipset member "192.168.0.0/16" needs an explicit operation`,
		},
		{
			"cidr flag beside a remove", ipsetMemberPolicy, "ipset:new",
			[]aclpolicy.IPSetMemberSpec{{Value: "10.5.0.0/16", CIDROnly: true}, {Value: "remove 10.1.0.0/16"}},
			`ipset member "10.5.0.0/16" needs an explicit operation`,
		},
		{
			"grammar error is surfaced", ipsetMemberPolicy, "ipset:x",
			members("drop 10.0.0.0/8"), `ipset member "drop 10.0.0.0/8" has an unsupported operation "drop"`,
		},
		{"no members", ipsetMemberPolicy, "ipset:x", nil, "ipset add requires at least one member"},
		{"bad name", ipsetMemberPolicy, "office", members("10.0.0.0/8"), `must have the ipset: prefix`},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			_, err := aclpolicy.AddIPSetMembers(mustLoad(t, test.policy), test.set, test.members)
			if err == nil {
				t.Fatalf("AddIPSetMembers(%s, %v) succeeded, want %q", test.set, test.members, test.want)
			}
			if !strings.Contains(err.Error(), test.want) {
				t.Errorf("error = %q; want it to contain %q", err, test.want)
			}
		})
	}
}

func TestAddIPSetMembersExplicitOperationErrorIsTyped(t *testing.T) {
	t.Parallel()
	_, err := aclpolicy.AddIPSetMembers(mustLoad(t, ipsetMemberPolicy), "ipset:x", members("remove 192.168.1.0/24"))
	var implicit *policycore.IPSetImplicitMemberError
	if !errors.As(err, &implicit) {
		t.Fatalf("error = %v; want IPSetImplicitMemberError", err)
	}
	if implicit.Member != "192.168.0.0/16" || implicit.Remove != "remove 192.168.1.0/24" {
		t.Errorf("error = %#v; want the existing member and the new remove", implicit)
	}
}

func TestAddIPSetMembersDoesNotDuplicateCanonicalMembers(t *testing.T) {
	t.Parallel()
	policy := mustLoad(t, `{
		"hosts": {"gw": "10.9.0.1"},
		"ipsets": {
			"ipset:base": ["10.0.0.0/8"],
			"ipset:x": ["add ipset:base", "add 10.1.2.3/8", "remove 2001:DB8::1-2001:DB8::9", "add host:gw"],
		},
	}`)
	edit, err := aclpolicy.AddIPSetMembers(policy, "ipset:x", members(
		"add  ipset:base", "add 10.0.0.0/8", "remove 2001:db8::1-2001:db8::9", "add host:gw", "add host:gw",
	))
	if err != nil {
		t.Fatal(err)
	}
	if edit.Changed() {
		t.Errorf("re-adding members in other spellings produced operations %#v", edit.Operations)
	}
	if !edit.Existed {
		t.Error("Existed = false for a present ipset")
	}
}

func TestAddIPSetMembersRuleRunsAfterIdempotence(t *testing.T) {
	t.Parallel()
	// A hand-written set that already violates the rule stays untouched by a
	// no-op add: the rule is about what the command would write.
	policy := mustLoad(t, `{"ipsets": {"ipset:x": ["10.0.0.0/8", "remove 10.1.0.0/16"]}}`)
	edit, err := aclpolicy.AddIPSetMembers(policy, "ipset:x", members("10.0.0.0/8"))
	if err != nil {
		t.Fatalf("no-op add on an already-mixed set = %v", err)
	}
	if edit.Changed() {
		t.Error("no-op add produced operations")
	}
}

func TestAddIPSetMembersCIDROnlyIsUnchanged(t *testing.T) {
	t.Parallel()
	policy := mustLoad(t, ipsetMemberPolicy)
	for _, test := range []struct{ value, want string }{
		{"10.0.0.1", `ipset member "10.0.0.1" is not a CIDR prefix: netip.ParsePrefix("10.0.0.1"): no '/'`},
		{"ipset:base", `ipset member "ipset:base" is not a CIDR prefix: netip.ParsePrefix("ipset:base"): no '/'`},
		{"host:gw", `ipset member "host:gw" is not a CIDR prefix: netip.ParsePrefix("host:gw"): no '/'`},
		{
			"remove 10.1.0.0/16",
			`ipset member "remove 10.1.0.0/16" is not a CIDR prefix: netip.ParsePrefix("remove 10.1.0.0/16"): ` +
				`ParseAddr("remove 10.1.0.0"): unexpected character (at "remove 10.1.0.0")`,
		},
	} {
		_, err := aclpolicy.AddIPSetMembers(policy, "ipset:x",
			[]aclpolicy.IPSetMemberSpec{{Value: test.value, CIDROnly: true}})
		if err == nil || err.Error() != test.want {
			t.Errorf("--cidr %q error = %v; want %q", test.value, err, test.want)
		}
	}
	// AddDefinition keeps routing the ipset kind through the CIDR-only path.
	_, err := aclpolicy.AddDefinition(policy, aclpolicy.DefinitionIPSet, "ipset:x", []string{"10.0.0.1"})
	if err == nil {
		t.Error("AddDefinition accepted a bare address for an ipset")
	}
}

func TestDefinitionReferencesSeeIPSetMembers(t *testing.T) {
	t.Parallel()
	policy := mustLoad(t, `{
		"hosts": {"gw": "10.9.0.1"},
		"ipsets": {
			"ipset:base": ["10.0.0.0/8"],
			"ipset:x": ["add ipset:base", "remove host:gw", "10.1.0.0/16"],
		},
	}`)
	for target, want := range map[string]string{
		"ipset:base": "ipsets[ipset:x][0]",
		"gw":         "ipsets[ipset:x][1]",
	} {
		if got := aclpolicy.DefinitionReferences(policy, target); !slices.Equal(got, []string{want}) {
			t.Errorf("DefinitionReferences(%s) = %v; want [%s]", target, got, want)
		}
	}
	if got := aclpolicy.DefinitionReferences(policy, "10.1.0.0/16"); len(got) != 0 {
		t.Errorf("a literal member counted as a reference: %v", got)
	}
	_, err := aclpolicy.RemoveDefinition(policy, aclpolicy.DefinitionIPSet, "ipset:base", false)
	if err == nil || !strings.Contains(err.Error(), "ipsets[ipset:x][0]") {
		t.Errorf("nested-only ipset removal = %v; want refusal naming ipsets[ipset:x][0]", err)
	}
}
