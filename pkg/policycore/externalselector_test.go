package policycore_test

import (
	"strings"
	"testing"

	"github.com/rshade/tsacl/pkg/policycore"
)

func TestParseExternalSelector(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		selector string
		want     policycore.ExternalSelector
	}{
		{
			name:     "group",
			selector: "group://partner/engineering",
			want: policycore.ExternalSelector{
				Kind:  policycore.ExternalSelectorGroup,
				Alias: "partner",
				Name:  "engineering",
			},
		},
		{
			name:     "tag",
			selector: "tag://production/batch",
			want: policycore.ExternalSelector{
				Kind:  policycore.ExternalSelectorTag,
				Alias: "production",
				Name:  "batch",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got, err := policycore.ParseExternalSelector(test.selector)
			if err != nil {
				t.Fatalf("ParseExternalSelector(%q) = %v, want nil", test.selector, err)
			}
			if got != test.want {
				t.Errorf("ParseExternalSelector(%q) = %#v, want %#v", test.selector, got, test.want)
			}
		})
	}
}

func TestParseExternalSelectorRejectsMalformedInput(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		selector string
		wantErr  string
	}{
		{name: "same-tailnet group", selector: "group:engineering", wantErr: "group:// or tag://"},
		{name: "same-tailnet tag", selector: "tag:batch", wantErr: "group:// or tag://"},
		{name: "unknown kind", selector: "user://partner/alice", wantErr: "group:// or tag://"},
		{name: "missing alias", selector: "group:///engineering", wantErr: "alias is required"},
		{name: "missing name", selector: "tag://partner/", wantErr: "name is required"},
		{name: "missing separator", selector: "group://partner", wantErr: "name is required"},
		{name: "extra path segment", selector: "group://partner/engineering/oncall", wantErr: "one alias and one name"},
		{name: "leading whitespace", selector: " group://partner/engineering", wantErr: "whitespace"},
		{name: "whitespace-only alias", selector: "group:// /engineering", wantErr: "alias is required"},
		{
			name:     "interior space in alias",
			selector: "group://part ner/engineering",
			wantErr:  "alias contains whitespace",
		},
		{name: "interior space in name", selector: "group://partner/eng ineering", wantErr: "name contains whitespace"},
		{name: "newline in name", selector: "group://partner/eng\nineering", wantErr: "name contains whitespace"},
		{name: "carriage return in name", selector: "tag://partner/batch\rjob", wantErr: "name contains whitespace"},
		{name: "NUL in name", selector: "group://partner/engineering\x00", wantErr: "non-printable"},
		{
			name:     "zero-width space in alias",
			selector: "group://\u200bpartner/engineering",
			wantErr:  "alias contains whitespace",
		},
		{
			name:     "group-prefixed name",
			selector: "group://partner/group:engineering",
			wantErr:  "must omit the group: prefix",
		},
		{name: "tag-prefixed name", selector: "tag://partner/tag:batch", wantErr: "must omit the tag: prefix"},
		{name: "cross-prefixed name", selector: "group://partner/tag:batch", wantErr: "must omit the tag: prefix"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got, err := policycore.ParseExternalSelector(test.selector)
			if err == nil {
				t.Fatalf("ParseExternalSelector(%q) = (%#v, nil), want an error", test.selector, got)
			}
			if !strings.Contains(err.Error(), test.wantErr) {
				t.Errorf(
					"ParseExternalSelector(%q) error = %q, want it to contain %q",
					test.selector, err, test.wantErr,
				)
			}
			if got != (policycore.ExternalSelector{}) {
				t.Errorf("ParseExternalSelector(%q) returned %#v with an error, want zero value", test.selector, got)
			}
		})
	}
}
