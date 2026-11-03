package policycore_test

import (
	"slices"
	"testing"

	"github.com/rshade/tsacl/pkg/policycore"
)

func TestEffectiveSrcPosture(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		own         []string
		fallback    []string
		want        []string
		fromDefault bool
	}{
		{
			name:        "own posture replaces the default",
			own:         []string{"posture:a"},
			fallback:    []string{"posture:b"},
			want:        []string{"posture:a"},
			fromDefault: false,
		},
		{
			name:        "empty own inherits the default",
			own:         nil,
			fallback:    []string{"posture:b"},
			want:        []string{"posture:b"},
			fromDefault: true,
		},
		{
			name:        "no posture anywhere is no gate",
			own:         nil,
			fallback:    nil,
			want:        nil,
			fromDefault: false,
		},
		{
			name:        "own posture with no default is its own gate",
			own:         []string{"posture:a"},
			fallback:    nil,
			want:        []string{"posture:a"},
			fromDefault: false,
		},
		{
			name:        "empty default with empty own is no gate",
			own:         []string{},
			fallback:    []string{},
			want:        nil,
			fromDefault: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, fromDefault := policycore.EffectiveSrcPosture(tc.own, tc.fallback)
			if !slices.Equal(got, tc.want) {
				t.Errorf("EffectiveSrcPosture(%v, %v) = %v, want %v", tc.own, tc.fallback, got, tc.want)
			}
			if fromDefault != tc.fromDefault {
				t.Errorf("EffectiveSrcPosture(%v, %v) fromDefault = %v, want %v",
					tc.own, tc.fallback, fromDefault, tc.fromDefault)
			}
		})
	}
}
