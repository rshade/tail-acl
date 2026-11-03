package policycore_test

import (
	"slices"
	"testing"

	"github.com/rshade/tail-acl/pkg/policycore"

	tailscale "tailscale.com/client/tailscale/v2"
)

func TestAddressContains(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		selector string
		query    string
		want     bool
	}{
		{name: "prefix contains narrower prefix", selector: "10.0.0.0/8", query: "10.1.0.0/16", want: true},
		{name: "prefix does not contain wider prefix", selector: "10.1.0.0/16", query: "10.0.0.0/8", want: false},
		{name: "prefix contains address", selector: "10.0.0.0/8", query: "10.2.3.4", want: true},
		{name: "prefix excludes outside address", selector: "10.0.0.0/8", query: "11.2.3.4", want: false},
		{name: "bracketed ipv6 address", selector: "fd7a:115c:a1e0::/48", query: "[fd7a:115c:a1e0::1]", want: true},
		{name: "equal addresses", selector: "1.2.3.4", query: "1.2.3.4", want: true},
		{name: "unequal addresses", selector: "1.2.3.4", query: "1.2.3.5", want: false},
		{name: "non-address values", selector: "tag:web", query: "tag:web", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := policycore.AddressContains(tt.selector, tt.query); got != tt.want {
				t.Errorf("AddressContains(%q, %q) = %v; want %v", tt.selector, tt.query, got, tt.want)
			}
		})
	}
}

func TestExpandAddressSelectorResolvesHostsAndIPSets(t *testing.T) {
	t.Parallel()

	policy := &tailscale.ACL{
		Hosts: map[string]string{
			"web":      "10.1.0.0/16",
			"alias":    "web",
			"db":       "10.9.0.1",
			"10.9.0.1": "192.0.2.1",
			"a":        "b",
			"b":        "10.10.20.1",
			"gw":       "tag:web",
		},
		IPSets: map[string][]string{"ipset:corp": {"10.1.0.0/16", "192.168.5.0/24"}},
	}
	tests := []struct {
		name     string
		selector string
		want     []string
	}{
		{name: "host resolves to cidr", selector: "web", want: []string{"10.1.0.0/16"}},
		{name: "host alias is not followed", selector: "alias", want: []string{"web"}},
		{name: "alias chain stops at the first value", selector: "a", want: []string{"b"}},
		{name: "literal host value is not looked up again", selector: "db", want: []string{"10.9.0.1"}},
		{name: "tag value is returned unchanged", selector: "gw", want: []string{"tag:web"}},
		{name: "ipset expands to members", selector: "ipset:corp", want: []string{"10.1.0.0/16", "192.168.5.0/24"}},
		{name: "unknown value passes through", selector: "tag:web", want: []string{"tag:web"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := policycore.ExpandAddressSelector(tt.selector, policy)
			if len(got) != len(tt.want) {
				t.Fatalf("ExpandAddressSelector(%q) = %v; want %v", tt.selector, got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("ExpandAddressSelector(%q)[%d] = %q; want %q", tt.selector, i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestExpandAddressSelectorTerminatesOnCycle(t *testing.T) {
	t.Parallel()

	policy := &tailscale.ACL{Hosts: map[string]string{"a": "b", "b": "a"}}
	got := policycore.ExpandAddressSelector("a", policy)
	if len(got) != 1 || got[0] != "b" {
		t.Errorf("cyclic host expansion = %v; want [b]", got)
	}
}

// TestExpandAddressSelectorMaterializesIPSets pins the #366 fix: an ipset
// member written with an operation, as a range, or as a host: reference used
// to pass through verbatim and match nothing.
func TestExpandAddressSelectorMaterializesIPSets(t *testing.T) {
	t.Parallel()

	policy := issue366Policy()
	policy.IPSets["ipset:broken"] = []string{"host:missing"}
	tests := []struct {
		name     string
		selector string
		want     []string
	}{
		{
			name:     "operations apply in order and merge to a minimal covering",
			selector: "ipset:trimmed",
			want: []string{
				"10.0.0.0/16", "10.2.0.0/15", "10.4.0.0/14", "10.8.0.0/13",
				"10.16.0.0/12", "10.32.0.0/11", "10.64.0.0/10", "10.128.0.0/9",
			},
		},
		{
			name:     "a range expands to prefixes",
			selector: "ipset:rng",
			want:     []string{"10.5.0.1/32", "10.5.0.2/31", "10.5.0.4/30", "10.5.0.8/31"},
		},
		{name: "a host reference renders as a host prefix", selector: "ipset:h", want: []string{"10.9.0.1/32"}},
		{name: "a fully removed set expands to nothing", selector: "ipset:cut", want: nil},
		{name: "an unmaterializable set expands to nothing", selector: "ipset:broken", want: nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := policycore.ExpandAddressSelector(tt.selector, policy)
			if !slices.Equal(got, tt.want) {
				t.Errorf("ExpandAddressSelector(%q) = %v; want %v", tt.selector, got, tt.want)
			}
		})
	}
}

func TestIsPublicAddress(t *testing.T) {
	t.Parallel()

	policy := &tailscale.ACL{Hosts: map[string]string{"office": "203.0.113.0/24"}}
	tests := []struct {
		name  string
		value string
		want  bool
	}{
		{name: "public v4 address", value: "8.8.8.8", want: true},
		{name: "private v4 address", value: "10.1.2.3", want: false},
		{name: "tailscale cgnat address", value: "100.101.102.103", want: false},
		{name: "loopback", value: "127.0.0.1", want: false},
		{name: "public prefix via host", value: "office", want: true},
		{name: "tailscale v6 range", value: "fd7a:115c:a1e0::1", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := policycore.IsPublicAddress(tt.value, policy); got != tt.want {
				t.Errorf("IsPublicAddress(%q) = %v; want %v", tt.value, got, tt.want)
			}
		})
	}
}

// TestAddressExpansionToleratesANilPolicy pins the guard that keeps a matcher
// holding no policy document usable. Address expansion runs on every selector
// that is not a group, so reading through a nil document panicked before any
// resolver could notice there was nothing to resolve against.
func TestAddressExpansionToleratesANilPolicy(t *testing.T) {
	t.Parallel()

	got := policycore.ExpandAddressSelector("web", nil)
	if len(got) != 1 || got[0] != "web" {
		t.Errorf("ExpandAddressSelector(web, nil) = %v, want [web]", got)
	}
	if !policycore.IsPublicAddress("8.8.8.8", nil) {
		t.Error("IsPublicAddress(8.8.8.8, nil) = false, want true")
	}
	if policycore.IsPublicAddress("10.0.0.1", nil) {
		t.Error("IsPublicAddress(10.0.0.1, nil) = true, want false")
	}
}
