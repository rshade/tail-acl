package ipcalc_test

import (
	"net/netip"
	"testing"

	"github.com/rshade/tsacl/pkg/ipcalc"
)

func TestAggregate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input []string
		want  []string
	}{
		{
			name:  "adjacent siblings",
			input: []string{"10.0.0.0/25", "10.0.0.128/25"},
			want:  []string{"10.0.0.0/24"},
		},
		{
			name:  "covered prefix",
			input: []string{"10.0.0.0/25", "10.0.0.0/24"},
			want:  []string{"10.0.0.0/24"},
		},
		{
			name: "four children merge recursively",
			input: []string{
				"10.0.0.192/26", "10.0.0.0/26", "10.0.0.128/26", "10.0.0.64/26",
			},
			want: []string{"10.0.0.0/24"},
		},
		{
			name:  "non mergeable ordered",
			input: []string{"10.1.0.0/24", "10.0.0.0/24"},
			want:  []string{"10.0.0.0/24", "10.1.0.0/24"},
		},
		{
			name:  "host bits masked",
			input: []string{"10.0.0.1/25", "10.0.0.129/25"},
			want:  []string{"10.0.0.0/24"},
		},
		{
			name:  "adjacent IPv6 siblings",
			input: []string{"2001:db8:0:8000::/49", "2001:db8::/49"},
			want:  []string{"2001:db8::/48"},
		},
		{
			name: "ULA blocks merge across levels",
			input: []string{
				"fd12:3456:789a:1::/64", "fd12:3456:789a:2::/63", "fd12:3456:789a::/64",
			},
			want: []string{"fd12:3456:789a::/62"},
		},
		{
			name:  "wide IPv6 prefix covers descendants",
			input: []string{"2000::/3", "2001:db8::/32", "3ffe::/16"},
			want:  []string{"2000::/3"},
		},
		{
			name:  "unmergeable IPv6 ordered",
			input: []string{"2001:db8:2::/48", "2001:db8::/48"},
			want:  []string{"2001:db8::/48", "2001:db8:2::/48"},
		},
		{
			name: "mixed families never merge and order IPv4 first",
			input: []string{
				"2001:db8::/49", "10.0.0.128/25", "2001:db8:0:8000::/49", "10.0.0.0/25",
			},
			want: []string{"10.0.0.0/24", "2001:db8::/48"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			input := make([]netip.Prefix, len(tt.input))
			for i, text := range tt.input {
				prefix, err := netip.ParsePrefix(text)
				if err != nil {
					t.Fatalf("ParsePrefix(%q): %v", text, err)
				}
				input[i] = prefix
			}

			got := ipcalc.Aggregate(input)
			if len(got) != len(tt.want) {
				t.Fatalf("len(Aggregate()) = %d, want %d (%v)", len(got), len(tt.want), got)
			}
			for i, want := range tt.want {
				if got[i].String() != want {
					t.Errorf("Aggregate()[%d] = %s, want %s", i, got[i], want)
				}
			}
		})
	}
}

func TestAggregateEmpty(t *testing.T) {
	t.Parallel()

	if got := ipcalc.Aggregate(nil); got != nil {
		t.Errorf("Aggregate(nil) = %v, want nil", got)
	}
}
