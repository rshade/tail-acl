package alpha_test

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

// TestMigrationTripwireDetectsSyntheticSDKSupport is the regression guard for
// a tripwire's detector, and each case is a shape the SDK could plausibly
// ship. The externalTailnets tripwire this detector first served fired at
// tailscale v2.11.0 and was retired with the migration it prompted; the
// detector stays because the next hand-modeled feature's tripwire calls it.
//
// The tripwire matches on the JSON field name alone. Gating it on structural
// equality with this package's model would invert its purpose: the closer the
// SDK came to this model, the more reliably a near-miss — a pointer element, one
// added field — would leave the guard silent. Any SDK shape carrying
// externalTailnets is the migration signal, because a shape that merely
// resembles this one is still a shape somebody has to reconcile by hand.
//
// The shape-varying cases below therefore look redundant against the current
// matcher, which reads only a field's name and tag, and they are kept anyway:
// an earlier revision of this guard did compare structure and went silent on
// exactly these shapes. They pin the contract that shape must not matter, so
// reintroducing a structural check fails here instead of years later on a
// dependency bump nobody connects to this file.
func TestMigrationTripwireDetectsSyntheticSDKSupport(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		aclType reflect.Type
	}{
		{name: "shape identical to this package's", aclType: reflect.TypeFor[syntheticSDKACL]()},
		{name: "map to a pointer config", aclType: reflect.TypeFor[syntheticPointerACL]()},
		{name: "config grew a field", aclType: reflect.TypeFor[syntheticExtendedACL]()},
		{name: "config left opaque", aclType: reflect.TypeFor[syntheticOpaqueACL]()},
		{name: "field promoted through embedding", aclType: reflect.TypeFor[syntheticEmbeddedACL]()},
		{name: "field carries no json tag", aclType: reflect.TypeFor[syntheticUntaggedACL]()},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			field, found := jsonFieldNamed(test.aclType, "externalTailnets")
			if !found {
				t.Fatal("migration tripwire did not recognize an SDK externalTailnets field")
			}
			if field.Name != "ExternalTailnets" {
				t.Errorf("migration tripwire reported field %q, want ExternalTailnets", field.Name)
			}
		})
	}
}

func TestMigrationTripwireIgnoresUnrelatedFields(t *testing.T) {
	t.Parallel()

	if field, found := jsonFieldNamed(reflect.TypeFor[syntheticUnrelatedACL](), "externalTailnets"); found {
		t.Errorf("migration tripwire matched unrelated field %q, want no match", field.Name)
	}
}

type syntheticSDKACL struct {
	ExternalTailnets map[string]syntheticExternalTailnetConfig `json:"externalTailnets,omitempty"`
}

type syntheticPointerACL struct {
	ExternalTailnets map[string]*syntheticExternalTailnetConfig `json:"externalTailnets,omitempty"`
}

type syntheticExtendedACL struct {
	ExternalTailnets map[string]struct {
		ExternalID                string   `json:"externalID"`
		AllowIncomingConnections  bool     `json:"allowIncomingConnections"`
		AllowExternalReferencesTo []string `json:"allowExternalReferencesTo,omitempty"`
		DisplayName               string   `json:"displayName,omitempty"`
	} `json:"externalTailnets,omitempty"`
}

type syntheticEmbeddedACL struct {
	syntheticSharingPolicy
}

type syntheticSharingPolicy struct {
	ExternalTailnets map[string]syntheticExternalTailnetConfig `json:"externalTailnets,omitempty"`
}

// syntheticUntaggedACL carries no json tag, so its marshaled name is the Go
// field name verbatim. Matching case-insensitively is what keeps this a signal;
// encoding/json resolves incoming keys case-insensitively too, so the guard and
// the decoder agree on what counts as this field.
type syntheticUntaggedACL struct {
	ExternalTailnets map[string]syntheticExternalTailnetConfig
}

type syntheticOpaqueACL struct {
	ExternalTailnets json.RawMessage `json:"externalTailnets,omitempty"`
}

type syntheticUnrelatedACL struct {
	ExternalTailnetPolicy map[string]string `json:"externalTailnetPolicy,omitempty"`
	Groups                map[string]string `json:"groups,omitempty"`
}

type syntheticExternalTailnetConfig struct {
	ExternalID                string   `json:"externalID"`
	AllowIncomingConnections  bool     `json:"allowIncomingConnections"`
	AllowExternalReferencesTo []string `json:"allowExternalReferencesTo,omitempty"`
}

// jsonFieldNamed reports the first exported field of aclType whose JSON name
// matches jsonName, whatever type that field carries. It is deliberately
// generic: AGENTS.md expects every feature hand-modeled in this package to carry
// its own migration tripwire, so the next one's test calls this rather than
// copying it with one string changed.
//
// It uses [reflect.VisibleFields] rather than ranging aclType.Fields() so a
// field the SDK promotes through an embedded policy struct is still seen; a
// refactor upstream must not be able to hide a migration signal behind
// embedding. The match is case-insensitive because an untagged field marshals
// under its Go name, and encoding/json resolves incoming keys case-insensitively
// too, so the guard and the decoder agree on what counts as this field.
func jsonFieldNamed(aclType reflect.Type, jsonName string) (reflect.StructField, bool) {
	for _, field := range reflect.VisibleFields(aclType) {
		if field.IsExported() && strings.EqualFold(jsonFieldName(field), jsonName) {
			return field, true
		}
	}
	return reflect.StructField{}, false
}

func jsonFieldName(field reflect.StructField) string {
	name, _, _ := strings.Cut(field.Tag.Get("json"), ",")
	if name == "" {
		return field.Name
	}
	return name
}
