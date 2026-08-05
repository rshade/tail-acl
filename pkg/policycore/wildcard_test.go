package policycore_test

import (
	"testing"

	"github.com/rshade/tailscale-utils/policycore"
)

func TestContainsLiteralWildcard(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		selectors []string
		want      bool
	}{
		{name: "empty", want: false},
		{name: "literal", selectors: []string{"tag:web", "*"}, want: true},
		{name: "trimmed literal", selectors: []string{"  *  "}, want: true},
		{name: "port remains caller responsibility", selectors: []string{"*:443"}, want: false},
		{name: "autogroup tagged is dynamic", selectors: []string{"autogroup:tagged"}, want: false},
		{name: "role autogroup is not literal", selectors: []string{"autogroup:admin"}, want: false},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			if got := policycore.ContainsLiteralWildcard(testCase.selectors); got != testCase.want {
				t.Errorf("ContainsLiteralWildcard(%v) = %t; want %t", testCase.selectors, got, testCase.want)
			}
		})
	}
}
