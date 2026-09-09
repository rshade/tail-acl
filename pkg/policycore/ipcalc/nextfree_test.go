package ipcalc_test

import (
	"net/netip"
	"testing"

	"github.com/rshade/tailscale-utils/policycore/ipcalc"
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
