package addrspace_test

import (
	"testing"

	"github.com/rshade/tailscale-utils/policycore/addrspace"
)

func TestOverlaps(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		a       string
		b       string
		want    bool
		wantErr bool
	}{
		{name: "identical prefixes", a: "10.0.0.0/8", b: "10.0.0.0/8", want: true},
		{name: "narrower prefix is contained", a: "10.0.0.0/8", b: "10.1.0.0/16", want: true},
		{name: "wider prefix contains narrower", a: "10.1.0.0/16", b: "10.0.0.0/8", want: true},
		{name: "disjoint prefixes", a: "10.0.0.0/8", b: "11.0.0.0/8", want: false},
		{name: "adjacent non-overlapping prefixes", a: "10.0.0.0/24", b: "10.0.1.0/24", want: false},
		{name: "address inside prefix", a: "10.1.2.3", b: "10.0.0.0/8", want: true},
		{name: "address outside prefix", a: "11.1.2.3", b: "10.0.0.0/8", want: false},
		{name: "equal addresses", a: "10.1.2.3", b: "10.1.2.3", want: true},
		{name: "unequal addresses", a: "10.1.2.3", b: "10.1.2.4", want: false},
		{name: "bracketed ipv6 address inside prefix", a: "[fd7a:115c:a1e0::1]", b: "fd7a:115c:a1e0::/48", want: true},
		{
			name: "ipv4-mapped ipv6 prefix contains plain ipv4 prefix",
			a:    "::ffff:10.0.0.0/104", b: "10.0.0.0/16", want: true,
		},
		{
			name: "ipv4-mapped ipv6 prefix disjoint from plain ipv4 prefix",
			a:    "::ffff:10.0.0.0/104", b: "11.0.0.0/8", want: false,
		},
		{
			name: "ipv4-mapped ipv6 prefix overlaps enclosing ipv6 prefix",
			a:    "::ffff:10.0.0.0/104", b: "::/0", want: true,
		},
		{
			name: "enclosing ipv6 prefix overlaps ipv4-mapped ipv6 prefix",
			a:    "::/0", b: "::ffff:10.0.0.0/104", want: true,
		},
		{
			name: "narrow ipv4-mapped-family prefix never overlaps plain ipv4",
			a:    "::ffff:0:0/64", b: "10.0.0.0/8", want: false,
		},
		{name: "missing closing bracket", a: "[fd7a:115c:a1e0::1", b: "fd7a:115c:a1e0::/48", wantErr: true},
		{name: "missing opening bracket", a: "fd7a:115c:a1e0::1]", b: "fd7a:115c:a1e0::/48", wantErr: true},
		{name: "nested brackets", a: "[[fd7a:115c:a1e0::1]]", b: "fd7a:115c:a1e0::/48", wantErr: true},
		{name: "malformed first argument", a: "not-a-cidr", b: "10.0.0.0/8", wantErr: true},
		{name: "malformed second argument", a: "10.0.0.0/8", b: "not-a-cidr", wantErr: true},
		{name: "both malformed", a: "not-a-cidr", b: "also-not-a-cidr", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := addrspace.Overlaps(tt.a, tt.b)
			if (err != nil) != tt.wantErr {
				t.Fatalf("Overlaps(%q, %q) error = %v; wantErr %v", tt.a, tt.b, err, tt.wantErr)
			}
			if err != nil {
				return
			}
			if got != tt.want {
				t.Errorf("Overlaps(%q, %q) = %v; want %v", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

func TestOverlappingPairs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		cidrs     []string
		wantPairs [][2]int
		wantErrs  []int
	}{
		{name: "empty input", cidrs: nil},
		{name: "single entry has no pairs", cidrs: []string{"10.0.0.0/8"}},
		{
			name:      "disjoint entries produce no pairs",
			cidrs:     []string{"10.0.0.0/8", "11.0.0.0/8", "12.0.0.0/8"},
			wantPairs: nil,
		},
		{
			name:      "overlapping entries are reported once each",
			cidrs:     []string{"10.0.0.0/8", "10.1.0.0/16", "11.0.0.0/8"},
			wantPairs: [][2]int{{0, 1}},
		},
		{
			name:      "mapped ipv6 entry retains ipv6 and ipv4 overlaps",
			cidrs:     []string{"::/0", "::ffff:10.0.0.0/104", "10.0.0.0/16"},
			wantPairs: [][2]int{{0, 1}, {1, 2}},
		},
		{
			name:      "every pair overlaps",
			cidrs:     []string{"10.0.0.0/8", "10.1.0.0/16", "10.2.0.0/16"},
			wantPairs: [][2]int{{0, 1}, {0, 2}},
		},
		{
			name:      "malformed entry is excluded but does not hide other overlaps",
			cidrs:     []string{"10.0.0.0/8", "garbage", "10.1.0.0/16", "11.0.0.0/8"},
			wantPairs: [][2]int{{0, 2}},
			wantErrs:  []int{1},
		},
		{
			name:      "malformed bracketed entry is excluded",
			cidrs:     []string{"10.0.0.0/8", "[[fd7a:115c:a1e0::1]]", "10.1.0.0/16"},
			wantPairs: [][2]int{{0, 2}},
			wantErrs:  []int{1},
		},
		{
			name:     "every entry malformed never panics",
			cidrs:    []string{"a", "b", "c"},
			wantErrs: []int{0, 1, 2},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			gotPairs, gotErrs := addrspace.OverlappingPairs(tt.cidrs)
			assertPairs(t, tt.cidrs, gotPairs, tt.wantPairs)
			assertErrIndices(t, tt.cidrs, gotErrs, tt.wantErrs)
		})
	}
}

func assertPairs(t *testing.T, cidrs []string, got, want [][2]int) {
	t.Helper()

	if len(got) != len(want) {
		t.Fatalf("OverlappingPairs(%v) pairs = %v; want %v", cidrs, got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("OverlappingPairs(%v) pairs[%d] = %v; want %v", cidrs, i, got[i], want[i])
		}
	}
}

func assertErrIndices(t *testing.T, cidrs []string, got map[int]error, wantIndices []int) {
	t.Helper()

	if len(got) != len(wantIndices) {
		t.Fatalf("OverlappingPairs(%v) errs = %v; want indices %v", cidrs, got, wantIndices)
	}
	for _, index := range wantIndices {
		if got[index] == nil {
			t.Errorf("OverlappingPairs(%v) errs[%d] = nil; want an error", cidrs, index)
		}
	}
}
