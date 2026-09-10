package policycore

import "testing"

// TestCrossTailnetSpecForCoversMalformedSelectors proves the descriptor claims
// a selector the parser rejects. Membership in the vocabulary and well-
// formedness are separate questions: if crossTailnetSpecFor disowned a
// mistyped selector, every view of it would fall through to the local
// vocabulary and report the typo as a definite non-match.
func TestCrossTailnetSpecForCoversMalformedSelectors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		selector   string
		wantOK     bool
		wantParsed bool
		wantAlias  string
	}{
		{
			name:       "well-formed group",
			selector:   "group://partner/eng",
			wantOK:     true,
			wantParsed: true,
			wantAlias:  "partner",
		},
		{
			name:       "well-formed tag",
			selector:   "tag://partner/batch",
			wantOK:     true,
			wantParsed: true,
			wantAlias:  "partner",
		},
		{name: "missing name", selector: "group://partner", wantOK: true},
		{name: "missing alias", selector: "group:///eng", wantOK: true},
		{name: "same-tailnet group", selector: "group:eng"},
		{name: "autogroup", selector: "autogroup:admin"},
		{name: "user", selector: "ada@example.com"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			spec, ok := crossTailnetSpecFor(test.selector)
			if ok != test.wantOK {
				t.Fatalf("crossTailnetSpecFor(%q) ok = %t, want %t", test.selector, ok, test.wantOK)
			}
			if !ok {
				return
			}
			if gotParsed := spec.parseErr == nil; gotParsed != test.wantParsed {
				t.Errorf("crossTailnetSpecFor(%q) parsed = %t, want %t (err %v)",
					test.selector, gotParsed, test.wantParsed, spec.parseErr)
			}
			if spec.selector.Alias != test.wantAlias {
				t.Errorf("crossTailnetSpecFor(%q) alias = %q, want %q",
					test.selector, spec.selector.Alias, test.wantAlias)
			}
		})
	}
}
