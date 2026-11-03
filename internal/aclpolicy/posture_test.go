package aclpolicy_test

import (
	"testing"

	"github.com/rshade/tail-acl/internal/aclpolicy"
)

func TestNormalizePostureName(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{name: "already prefixed", input: "posture:labCompliant", want: "posture:labCompliant"},
		{name: "bare name is auto-prefixed", input: "labCompliant", want: "posture:labCompliant"},
		{
			name:  "remainder may itself contain colons",
			input: "posture:with:extra:colons",
			want:  "posture:with:extra:colons",
		},
		{name: "prefix alone with no name", input: "posture:", wantErr: true},
		{name: "empty name", input: "", wantErr: true},
		{name: "wrong prefix tag", input: "tag:web", wantErr: true},
		{name: "wrong prefix group", input: "group:x", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := aclpolicy.NormalizePostureName(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("NormalizePostureName(%q) = %q, want an error", tc.input, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("NormalizePostureName(%q) unexpected error: %v", tc.input, err)
			}
			if got != tc.want {
				t.Errorf("NormalizePostureName(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestValidatePostureReference(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{name: "valid reference", input: "posture:labCompliant"},
		{name: "prefix alone with no name", input: "posture:", wantErr: true},
		{name: "empty value", input: "", wantErr: true},
		{name: "wrong prefix", input: "tag:web", wantErr: true},
		{
			// The deliberate asymmetry with NormalizePostureName (see decision
			// #3 in the plan): a bare name is rejected here, not auto-prefixed.
			name:    "bare name is rejected, not auto-prefixed",
			input:   "labCompliant",
			wantErr: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := aclpolicy.ValidatePostureReference(tc.input)
			if tc.wantErr && err == nil {
				t.Errorf("ValidatePostureReference(%q) = nil, want an error", tc.input)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("ValidatePostureReference(%q) = %v, want nil", tc.input, err)
			}
		})
	}
}
