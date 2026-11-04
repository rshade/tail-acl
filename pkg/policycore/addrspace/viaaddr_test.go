package addrspace_test

import (
	"testing"

	"github.com/rshade/tsacl/pkg/policycore/addrspace"
)

func TestSiteID(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		cidr string
		want uint32
		ok   bool
	}{
		{name: "zero", cidr: "fd7a:115c:a1e0:b1a::/96", want: 0, ok: true},
		{name: "one", cidr: "fd7a:115c:a1e0:b1a:0:1:a00:0/104", want: 1, ok: true},
		{name: "mid range", cidr: "fd7a:115c:a1e0:b1a:0:1234:c0a8:100/120", want: 0x1234, ok: true},
		{name: "maximum", cidr: "fd7a:115c:a1e0:b1a:0:ffff:c000:201/128", want: 0xffff, ok: true},
		{name: "via range too short", cidr: "fd7a:115c:a1e0:b1a::/95"},
		{name: "site ID above maximum", cidr: "fd7a:115c:a1e0:b1a:1:0::/128"},
		{name: "outside via range", cidr: "2001:db8::/32"},
		{name: "malformed CIDR", cidr: "not-a-cidr"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got, ok := addrspace.SiteID(test.cidr)
			if ok != test.ok || got != test.want {
				t.Errorf("SiteID(%q) = (%d, %v); want (%d, %v)", test.cidr, got, ok, test.want, test.ok)
			}
		})
	}
}

func TestIsViaPrefix(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		cidr string
		want bool
	}{
		{name: "valid via prefix", cidr: "fd7a:115c:a1e0:b1a:0:2a:a00:0/104", want: true},
		{name: "default route width (wider than via range)", cidr: "fd7a:115c:a1e0:b1a::/0", want: false},
		{name: "ULA-wide prefix (wider than via range)", cidr: "fd7a:115c:a1e0:b1a::/8", want: false},
		{name: "same base address, one /48 wider than via range", cidr: "fd7a:115c:a1e0:b1a::/48", want: false},
		{name: "one bit wider than via range", cidr: "fd7a:115c:a1e0:b1a::/63", want: false},
		{name: "via range too short for site ID extraction", cidr: "fd7a:115c:a1e0:b1a::/64", want: true},
		{name: "via range with reserved site ID", cidr: "fd7a:115c:a1e0:b1a:1:0::/128", want: true},
		{name: "ordinary IPv6 route", cidr: "2001:db8::/32"},
		{name: "Tailscale ULA outside via range", cidr: "fd7a:115c:a1e0::/48"},
		{name: "ordinary IPv4 route", cidr: "10.0.0.0/8"},
		{name: "bare via address", cidr: "fd7a:115c:a1e0:b1a::"},
		{name: "malformed CIDR", cidr: "not-a-cidr"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			if got := addrspace.IsViaPrefix(test.cidr); got != test.want {
				t.Errorf("IsViaPrefix(%q) = %v; want %v", test.cidr, got, test.want)
			}
		})
	}
}
