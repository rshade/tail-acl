package alpha_test

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/rshade/tailscale-utils/policycore/alpha"
)

func TestExternalTailnetsUnmarshalVerbatimPolicyShape(t *testing.T) {
	t.Parallel()

	const document = `{"externalTailnets":{"partner":{"externalID":"tailnet-123","allowIncomingConnections":false,"allowExternalReferencesTo":["group:engineering","tag:batch"]}}}`
	var decoded struct {
		ExternalTailnets alpha.ExternalTailnets `json:"externalTailnets"`
	}
	if err := json.Unmarshal([]byte(document), &decoded); err != nil {
		t.Fatalf("json.Unmarshal() = %v, want nil", err)
	}

	want := alpha.ExternalTailnets{
		"partner": {
			ExternalID:                "tailnet-123",
			AllowIncomingConnections:  false,
			AllowExternalReferencesTo: []string{"group:engineering", "tag:batch"},
		},
	}
	if !reflect.DeepEqual(decoded.ExternalTailnets, want) {
		t.Errorf("ExternalTailnets = %#v, want %#v", decoded.ExternalTailnets, want)
	}
}

func TestExternalTailnetConfigJSONRoundTrip(t *testing.T) {
	t.Parallel()

	const document = `{"externalID":"tailnet-123","allowIncomingConnections":false,"allowExternalReferencesTo":["group:engineering","tag:batch"]}`
	var decoded alpha.ExternalTailnetConfig
	if err := json.Unmarshal([]byte(document), &decoded); err != nil {
		t.Fatalf("json.Unmarshal() = %v, want nil", err)
	}

	encoded, err := json.Marshal(decoded)
	if err != nil {
		t.Fatalf("json.Marshal() = %v, want nil", err)
	}
	if string(encoded) != document {
		t.Errorf("round-trip JSON = %s, want %s", encoded, document)
	}
}

func TestExternalTailnetConfigAllowsOmittedReferenceList(t *testing.T) {
	t.Parallel()

	const document = `{"externalID":"tailnet-456","allowIncomingConnections":true}`
	var config alpha.ExternalTailnetConfig
	if err := json.Unmarshal([]byte(document), &config); err != nil {
		t.Fatalf("json.Unmarshal() = %v, want nil", err)
	}
	if config.ExternalID != "tailnet-456" || !config.AllowIncomingConnections {
		t.Errorf("ExternalTailnetConfig = %#v, want ID tailnet-456 with incoming connections allowed", config)
	}
	if config.AllowExternalReferencesTo != nil {
		t.Errorf("AllowExternalReferencesTo = %#v, want nil for an omitted list", config.AllowExternalReferencesTo)
	}
}

func TestParseExternalSelector(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		selector string
		want     alpha.ExternalSelector
	}{
		{
			name:     "group",
			selector: "group://partner/engineering",
			want: alpha.ExternalSelector{
				Kind:  alpha.ExternalSelectorGroup,
				Alias: "partner",
				Name:  "engineering",
			},
		},
		{
			name:     "tag",
			selector: "tag://production/batch",
			want: alpha.ExternalSelector{
				Kind:  alpha.ExternalSelectorTag,
				Alias: "production",
				Name:  "batch",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got, err := alpha.ParseExternalSelector(test.selector)
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

			got, err := alpha.ParseExternalSelector(test.selector)
			if err == nil {
				t.Fatalf("ParseExternalSelector(%q) = (%#v, nil), want an error", test.selector, got)
			}
			if !strings.Contains(err.Error(), test.wantErr) {
				t.Errorf(
					"ParseExternalSelector(%q) error = %q, want it to contain %q",
					test.selector, err, test.wantErr,
				)
			}
			if got != (alpha.ExternalSelector{}) {
				t.Errorf("ParseExternalSelector(%q) returned %#v with an error, want zero value", test.selector, got)
			}
		})
	}
}

func TestRepositoryFeaturesIncludesDeclarativeNodeSharing(t *testing.T) {
	t.Parallel()

	registry := alpha.NewRegistry()
	for _, feature := range alpha.RepositoryFeatures() {
		if err := registry.Register(feature); err != nil {
			t.Fatalf("Register(%q) = %v, want nil", feature.Name, err)
		}
	}

	got, ok := registry.Lookup("declarative-node-sharing")
	if !ok {
		t.Fatal("RepositoryFeatures() does not include declarative-node-sharing")
	}
	want := alpha.Feature{
		Name:        "declarative-node-sharing",
		DocURL:      "https://tailscale.com/docs/features/declarative-node-sharing",
		ModeledDate: time.Date(2026, time.September, 3, 0, 0, 0, 0, time.UTC),
		Stage:       alpha.StageAlpha,
	}
	if got != want {
		t.Errorf("declarative-node-sharing feature = %+v, want %+v", got, want)
	}
}
