package policycore_test

import (
	"testing"

	"github.com/rshade/tailscale-utils/policycore"

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
		Hosts:  map[string]string{"web": "10.1.0.0/16", "alias": "web"},
		IPSets: map[string][]string{"ipset:corp": {"10.1.0.0/16", "192.168.5.0/24"}},
	}
	tests := []struct {
		name     string
		selector string
		want     []string
	}{
		{name: "host resolves to cidr", selector: "web", want: []string{"10.1.0.0/16"}},
		{name: "host alias resolves transitively", selector: "alias", want: []string{"10.1.0.0/16"}},
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
	if got := policycore.ExpandAddressSelector("a", policy); len(got) != 0 {
		t.Errorf("cyclic host expansion = %v; want empty", got)
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
