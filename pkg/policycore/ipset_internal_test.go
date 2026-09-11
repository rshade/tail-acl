package policycore

import "testing"

func TestIPSetOperationOf(t *testing.T) {
	t.Parallel()

	for raw, want := range map[string]IPSetOperation{
		"10.0.0.0/8":           IPSetImplicit,
		"add 10.0.0.0/8":       IPSetAdd,
		" remove  ipset:base ": IPSetRemove,
		"add":                  IPSetImplicit,
		"add a b":              IPSetImplicit,
		"Remove 10.0.0.0/8":    IPSetImplicit,
	} {
		if got := ipsetOperationOf(raw); got != want {
			t.Errorf("ipsetOperationOf(%q) = %q; want %q", raw, got, want)
		}
	}
}
