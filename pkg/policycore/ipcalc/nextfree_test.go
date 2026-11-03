package ipcalc_test

import (
	"net/netip"
	"strconv"
	"testing"

	"github.com/rshade/tail-acl/pkg/policycore/ipcalc"
)

func TestNextFree(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		pool       string
		targetBits int
		taken      []string
		want       string
		wantOK     bool
	}{
		{
			name: "empty pool returns its first child",
			pool: "10.0.0.0/24", targetBits: 26,
			want: "10.0.0.0/26", wantOK: true,
		},
		{
			name: "adjacent exclusions leave next aligned child",
			pool: "10.0.0.0/24", targetBits: 26,
			taken: []string{"10.0.0.0/26", "10.0.0.64/26"},
			want:  "10.0.0.128/26", wantOK: true,
		},
		{
			name: "containing exclusion blocks target child",
			pool: "10.0.0.0/24", targetBits: 26,
			taken: []string{"10.0.0.0/25"},
			want:  "10.0.0.128/26", wantOK: true,
		},
		{
			name: "contained exclusion blocks enclosing target child",
			pool: "10.0.0.0/24", targetBits: 26,
			taken: []string{"10.0.0.1/32"},
			want:  "10.0.0.64/26", wantOK: true,
		},
		{
			name: "exhausted pool has no result",
			pool: "10.0.0.0/24", targetBits: 26,
			taken:  []string{"10.0.0.0/24"},
			wantOK: false,
		},
		{
			name: "mixed family and outside exclusions are ignored",
			pool: "10.0.0.0/24", targetBits: 26,
			taken: []string{"2001:db8::/32", "10.1.0.0/16"},
			want:  "10.0.0.0/26", wantOK: true,
		},
		{
			name: "large gap search does not enumerate children",
			pool: "10.0.0.0/8", targetBits: 32,
			taken: []string{"10.0.0.0/9"},
			want:  "10.128.0.0/32", wantOK: true,
		},
		{
			name: "ipv6 is family agnostic",
			pool: "2001:db8::/126", targetBits: 128,
			taken: []string{"2001:db8::/128", "2001:db8::1/128"},
			want:  "2001:db8::2/128", wantOK: true,
		},
		{
			name: "ipv6 skips half a /32 to find a /48",
			pool: "2001:db8::/32", targetBits: 48,
			taken: []string{"2001:db8::/33"},
			want:  "2001:db8:8000::/48", wantOK: true,
		},
		{
			name: "ipv6 skips billions of occupied /64 children",
			pool: "2001:db8::/32", targetBits: 64,
			taken: []string{"2001:db8::/33"},
			want:  "2001:db8:8000::/64", wantOK: true,
		},
		{
			name: "ipv6 skips half the address space",
			pool: "::/0", targetBits: 128,
			taken: []string{"::/1"},
			want:  "8000::/128", wantOK: true,
		},
		{
			name: "ipv6 unaligned host exclusion rounds to next child",
			pool: "2001:db8::1234/32", targetBits: 48,
			taken: []string{"2001:db8::1/128", "2001:db8:2::/48"},
			want:  "2001:db8:1::/48", wantOK: true,
		},
		{
			name: "ipv6 merges unsorted overlapping and adjacent exclusions",
			pool: "2001:db8::/32", targetBits: 48,
			taken: []string{"2001:db8:1::/48", "2001:db8::/49", "2001:db8::1/48"},
			want:  "2001:db8:2::/48", wantOK: true,
		},
		{
			name: "ipv6 ignores ipv4 and outside exclusions",
			pool: "2001:db8::/32", targetBits: 48,
			taken: []string{"0.0.0.0/0", "2001:db9::/32"},
			want:  "2001:db8::/48", wantOK: true,
		},
		{
			name: "ipv6 /127 can return its last host",
			pool: "2001:db8::/127", targetBits: 128,
			taken: []string{"2001:db8::/128"},
			want:  "2001:db8::1/128", wantOK: true,
		},
		{
			name: "ipv6 /127 exhaustion",
			pool: "2001:db8::/127", targetBits: 128,
			taken: []string{"2001:db8::/128", "2001:db8::1/128"},
		},
		{
			name: "ipv6 maximum address is a valid child",
			pool: "ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe/127", targetBits: 128,
			taken: []string{"ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe/128"},
			want:  "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128", wantOK: true,
		},
		{
			name: "ipv6 maximum host pool is available",
			pool: "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128", targetBits: 128,
			want: "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128", wantOK: true,
		},
		{
			name: "ipv6 maximum host exhaustion does not wrap",
			pool: "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128", targetBits: 128,
			taken: []string{"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128"},
		},
		{
			name: "ipv6 containing exclusion exhausts pool",
			pool: "2001:db8::/32", targetBits: 48,
			taken: []string{"::/0"},
		},
		{
			name: "ipv6 target shorter than pool",
			pool: "2001:db8::/32", targetBits: 31,
		},
		{
			name: "ipv6 target exceeds address width",
			pool: "2001:db8::/32", targetBits: 129,
		},
		{
			name: "invalid target has no result",
			pool: "10.0.0.0/24", targetBits: 20,
			wantOK: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			pool := netip.MustParsePrefix(test.pool)
			taken := make([]netip.Prefix, len(test.taken))
			for index, prefix := range test.taken {
				taken[index] = netip.MustParsePrefix(prefix)
			}

			got, gotOK := ipcalc.NextFree(pool, test.targetBits, taken)
			if gotOK != test.wantOK {
				t.Fatalf("NextFree() ok = %t, want %t (prefix = %s)", gotOK, test.wantOK, got)
			}
			if test.wantOK && got.String() != test.want {
				t.Errorf("NextFree() = %s, want %s", got, test.want)
			}
		})
	}
}

func BenchmarkNextFreeIPv6(b *testing.B) {
	pool := netip.MustParsePrefix("2001:db8::/32")
	taken := []netip.Prefix{netip.MustParsePrefix("2001:db8::/33")}
	for _, bits := range []int{48, 64, 128} {
		b.Run(strconv.Itoa(bits), func(b *testing.B) {
			want := netip.PrefixFrom(netip.MustParseAddr("2001:db8:8000::"), bits)
			b.ReportAllocs()
			for b.Loop() {
				got, ok := ipcalc.NextFree(pool, bits, taken)
				if !ok || got != want {
					b.Fatalf("NextFree() = %s, %t; want %s, true", got, ok, want)
				}
			}
		})
	}
}
