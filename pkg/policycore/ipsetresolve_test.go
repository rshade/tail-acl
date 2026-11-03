package policycore_test

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/rshade/tsacl/pkg/policycore"

	tailscale "tailscale.com/client/tailscale/v2"
)

// issue366Policy is the policy #366 measured against the control plane: every
// form the wire enforced that the old resolver passed through verbatim.
func issue366Policy() *tailscale.ACL {
	return &tailscale.ACL{
		Hosts: map[string]string{"gw": "10.9.0.1"},
		IPSets: map[string][]string{
			"ipset:base":    {"10.0.0.0/8"},
			"ipset:trimmed": {"add ipset:base", "remove 10.1.0.0/16"},
			"ipset:rng":     {"10.5.0.1-10.5.0.9"},
			"ipset:h":       {"host:gw"},
			"ipset:cut":     {"add host:gw", "remove 10.9.0.0/24"},
			"ipset:readded": {"add 198.51.100.0/24", "remove 198.51.100.0/24", "add 198.51.100.2-198.51.100.3"},
		},
	}
}

func covers(prefixes []netip.Prefix, address string) bool {
	addr := netip.MustParseAddr(address)
	for _, prefix := range prefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func TestResolveIPSetAppliesMembersInOrder(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		set     string
		inside  []string
		outside []string
	}{
		{
			name:    "a remove withdraws part of an added set",
			set:     "ipset:trimmed",
			inside:  []string{"10.2.0.5", "10.0.0.1"},
			outside: []string{"10.1.0.5"},
		},
		{
			name:    "a range expands to the addresses between its ends",
			set:     "ipset:rng",
			inside:  []string{"10.5.0.1", "10.5.0.4", "10.5.0.9"},
			outside: []string{"10.5.0.0", "10.5.0.10"},
		},
		{
			name:   "a host reference resolves through Hosts",
			set:    "ipset:h",
			inside: []string{"10.9.0.1"},
		},
		{
			name:    "a remove withdraws a host alias inside the removed range",
			set:     "ipset:cut",
			outside: []string{"10.9.0.1"},
		},
	}
	policy := issue366Policy()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := policycore.ResolveIPSet(tt.set, policy)
			if err != nil {
				t.Fatalf("ResolveIPSet(%q) error = %v", tt.set, err)
			}
			for _, address := range tt.inside {
				if !covers(got, address) {
					t.Errorf("ResolveIPSet(%q) = %v does not cover %s", tt.set, got, address)
				}
			}
			for _, address := range tt.outside {
				if covers(got, address) {
					t.Errorf("ResolveIPSet(%q) = %v covers %s", tt.set, got, address)
				}
			}
		})
	}
}

func TestResolveIPSetLetsALaterAddRecontributeRemovedSpace(t *testing.T) {
	t.Parallel()

	got, err := policycore.ResolveIPSet("ipset:readded", issue366Policy())
	if err != nil {
		t.Fatalf("ResolveIPSet(ipset:readded) error = %v", err)
	}
	want := []netip.Prefix{netip.MustParsePrefix("198.51.100.2/31")}
	if !slices.Equal(got, want) {
		t.Errorf("ResolveIPSet(ipset:readded) = %v, want %v", got, want)
	}
}

// TestResolveIPSetMatchesTheWire pins two rows the control plane compiled for
// a subnet router (#366, 2026-09-12 and 2026-09-15): the exact covering, not
// just containment, because the node enforces the compiled form.
func TestResolveIPSetMatchesTheWire(t *testing.T) {
	t.Parallel()

	policy := &tailscale.ACL{
		Hosts: map[string]string{"site01-app": "10.101.10.5"},
		IPSets: map[string][]string{
			"ipset:19370":              {"add 10.10.20.0/23", "remove 10.10.20.0/24", "add 10.10.20.1"},
			"ipset:probe-trimmed-host": {"add 10.101.10.0/24", "remove host:site01-app"},
		},
	}
	tests := []struct {
		set  string
		want []string
	}{
		{"ipset:19370", []string{"10.10.20.1/32", "10.10.21.0/24"}},
		{"ipset:probe-trimmed-host", []string{
			"10.101.10.0/30", "10.101.10.4/32", "10.101.10.6/31", "10.101.10.8/29",
			"10.101.10.16/28", "10.101.10.32/27", "10.101.10.64/26", "10.101.10.128/25",
		}},
	}
	for _, tt := range tests {
		t.Run(tt.set, func(t *testing.T) {
			t.Parallel()

			got, err := policycore.ResolveIPSet(tt.set, policy)
			if err != nil {
				t.Fatalf("ResolveIPSet(%q) error = %v", tt.set, err)
			}
			want := make([]netip.Prefix, len(tt.want))
			for i, prefix := range tt.want {
				want[i] = netip.MustParsePrefix(prefix)
			}
			if !slices.Equal(got, want) {
				t.Errorf("ResolveIPSet(%q) = %v, want %v", tt.set, got, want)
			}
		})
	}
}

func TestResolveIPSetRejectsWhatItCannotMaterialize(t *testing.T) {
	t.Parallel()

	policy := &tailscale.ACL{
		Hosts: map[string]string{"gw": "10.9.0.1", "a": "b", "b": "10.10.20.1"},
		IPSets: map[string][]string{
			"ipset:bare":     {"gw"},
			"ipset:nohost":   {"host:missing"},
			"ipset:chain":    {"host:a"},
			"ipset:internet": {"add autogroup:internet", "remove 8.8.8.0/24"},
			"ipset:noset":    {"10.0.0.0/8", "ipset:missing"},
			"ipset:a":        {"ipset:b"},
			"ipset:b":        {"ipset:a"},
			"ipset:mixed":    {"10.0.0.0/8", "remove 10.1.0.0/16"},
		},
	}
	tests := []struct {
		name string
		set  string
		want []string
	}{
		{name: "a bare alias is not a member", set: "ipset:bare", want: []string{"ipset:bare", "member 1"}},
		{
			name: "an implicit member beside a remove",
			set:  "ipset:mixed",
			want: []string{"ipset:mixed", `"10.0.0.0/8"`, `"remove 10.1.0.0/16"`},
		},
		{name: "an undefined host reference", set: "ipset:nohost", want: []string{"host:missing"}},
		{name: "a host alias that names another alias", set: "ipset:chain", want: []string{"host:a", `"b"`}},
		{
			name: "a member the wire accepts but the grammar does not",
			set:  "ipset:internet",
			want: []string{"ipset:internet", "member 1"},
		},
		{name: "an undefined ipset reference", set: "ipset:noset", want: []string{"member 2", "ipset:missing"}},
		{name: "a cyclic ipset reference", set: "ipset:a", want: []string{"cyclic", "ipset:a"}},
		{name: "a selector that is not an ipset", set: "ipset:undefined", want: []string{"not a defined ipset"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := policycore.ResolveIPSet(tt.set, policy)
			if err == nil {
				t.Fatalf("ResolveIPSet(%q) = %v, want an error", tt.set, got)
			}
			if got != nil {
				t.Errorf("ResolveIPSet(%q) returned prefixes %v alongside an error", tt.set, got)
			}
			for _, fragment := range tt.want {
				if !strings.Contains(err.Error(), fragment) {
					t.Errorf("ResolveIPSet(%q) error = %q, want it to name %q", tt.set, err, fragment)
				}
			}
		})
	}
}

func TestResolveIPSetResolvesADiamondOnceAndNotAsACycle(t *testing.T) {
	t.Parallel()

	policy := &tailscale.ACL{
		IPSets: map[string][]string{
			"ipset:top":    {"ipset:left", "ipset:right"},
			"ipset:left":   {"ipset:shared"},
			"ipset:right":  {"ipset:shared"},
			"ipset:shared": {"192.0.2.0/24"},
		},
	}
	got, err := policycore.ResolveIPSet("ipset:top", policy)
	if err != nil {
		t.Fatalf("ResolveIPSet(ipset:top) error = %v", err)
	}
	want := []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}
	if !slices.Equal(got, want) {
		t.Errorf("ResolveIPSet(ipset:top) = %v, want %v", got, want)
	}
}

func TestResolveIPSetRejectsANilPolicy(t *testing.T) {
	t.Parallel()

	if got, err := policycore.ResolveIPSet("ipset:x", nil); err == nil {
		t.Errorf("ResolveIPSet(ipset:x, nil) = %v, want an error", got)
	}
}

// chainPolicy nests length ipsets so ipset:s0 reaches the leaf prefix only
// after length-1 references.
func chainPolicy(length int) *tailscale.ACL {
	sets := make(map[string][]string, length)
	for i := range length - 1 {
		sets[fmt.Sprintf("ipset:s%d", i)] = []string{fmt.Sprintf("ipset:s%d", i+1)}
	}
	sets[fmt.Sprintf("ipset:s%d", length-1)] = []string{"10.0.0.0/8"}
	return &tailscale.ACL{IPSets: sets}
}

func TestResolveIPSetBoundsNestingDepth(t *testing.T) {
	t.Parallel()

	if _, err := policycore.ResolveIPSet("ipset:s0", chainPolicy(128)); err != nil {
		t.Errorf("a 128-level chain: error = %v, want nil", err)
	}
	if _, err := policycore.ResolveIPSet("ipset:s0", chainPolicy(129)); err == nil {
		t.Error("a 129-level chain resolved; want the depth error")
	}
}

func TestResolveIPSetBoundsExpansion(t *testing.T) {
	t.Parallel()

	// Every other address, so no two members abut and the builder cannot
	// merge them: 65537 members materialize to 65537 prefixes.
	const count = 65537
	members := make([]string, 0, count)
	for i := range count {
		offset := 2 * i
		members = append(members, fmt.Sprintf("10.%d.%d.%d", offset>>16, (offset>>8)&0xff, offset&0xff))
	}
	policy := &tailscale.ACL{IPSets: map[string][]string{"ipset:wide": members}}
	got, err := policycore.ResolveIPSet("ipset:wide", policy)
	if err == nil {
		t.Fatalf("ResolveIPSet(ipset:wide) = %d prefixes, want the expansion error", len(got))
	}
	if !strings.Contains(err.Error(), "ipset:wide") {
		t.Errorf("ResolveIPSet(ipset:wide) error = %q, want it to name the set", err)
	}
	policy.IPSets["ipset:wide"] = members[:count-1]
	if _, err = policycore.ResolveIPSet("ipset:wide", policy); err != nil {
		t.Errorf("ResolveIPSet(ipset:wide) at the limit: error = %v, want nil", err)
	}
}
