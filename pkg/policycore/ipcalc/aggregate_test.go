package ipcalc_test

import (
	"net/netip"
	"testing"

	"github.com/rshade/tailscale-utils/policycore/ipcalc"
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
