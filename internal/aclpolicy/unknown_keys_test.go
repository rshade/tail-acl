package aclpolicy //nolint:testpackage // white-box: guards the derived policy-key catalog against the editorial syntax catalog.

import (
	"strings"
	"testing"
)

func TestClassifyDoesNotClaimAKeyIsNotTailscales(t *testing.T) {
	t.Parallel()
	// Reflecting over Policy proves what this build models and nothing about
	// what Tailscale documents. A key in alpha or beta ahead of GA is a real
	// policy key this pin has not caught up to, so the verdict must not read as
	// "no such key" -- that is what sends an operator to delete live policy.
	catalog := policyKeyCatalog{modeled: map[string]string{"ipsets": "ipsets"}}
	const want = "not modeled by this build"
	if got := catalog.classify("vipRoutes"); got != want {
		t.Errorf("classify(vipRoutes) = %q, want %q", got, want)
	}
	// A near miss still earns a hint, so a plain typo stays cheap to fix.
	if got := catalog.classify("ipsat"); got != want+`; did you mean "ipsets"?` {
		t.Errorf("classify(ipsat) = %q, want a spelling hint", got)
	}
}

func TestPolicyKeyCatalogPrefersShadowingSSHField(t *testing.T) {
	t.Parallel()
	// Policy.SSH shadows the promoted ACL.SSH. jsonObjectFields resolves that
	// collision by declaration order, not by encoding/json's depth rule, so it
	// agrees with the decoder only because tailscale.ACL is embedded above
	// SSH []SSHRule in Policy. Moving that field up would silently swap the
	// type and drop the local acceptEnv extension's location hint with every
	// other test still passing.
	catalog := buildPolicyKeyCatalog()
	if got := catalog.nested["acceptenv"]; len(got) != 1 || got[0] != "ssh[].acceptEnv" {
		t.Fatalf("nested acceptEnv locations = %#v, want [ssh[].acceptEnv]", got)
	}
}

func TestPolicyKeyCatalogDerivesRoutesLocation(t *testing.T) {
	t.Parallel()
	got := buildPolicyKeyCatalog().nested["routes"]
	if len(got) != 1 || got[0] != "autoApprovers.routes" {
		t.Fatalf("nested routes locations = %#v, want [autoApprovers.routes]", got)
	}
}

func TestPolicyKeyCatalogRendersCollectionHops(t *testing.T) {
	t.Parallel()
	// A hint is only actionable if it names a location an operator can write.
	// Eliding the collection hop rendered attrConfig's per-attribute objects as
	// "attrConfig.type" and every rule-array field as "acls.src", both of which
	// read as struct paths that do not exist in a policy file.
	catalog := buildPolicyKeyCatalog()
	for key, want := range map[string]string{
		"type":       "attrConfig.<key>.type",
		"avoid":      "derpMap.regions.<key>.avoid",
		"certname":   "derpMap.regions.<key>.nodes[].certName",
		"connectors": "nodeAttrs[].app.<key>[].connectors",
	} {
		got := catalog.nested[key]
		if len(got) != 1 || got[0] != want {
			t.Errorf("nested[%q] = %#v, want [%s]", key, got, want)
		}
	}
}

func TestSuggestPolicyKeyIgnoresOversizedNames(t *testing.T) {
	t.Parallel()
	// The rune-count prefilter must not change any answer it is allowed to
	// reach: a name too long to be within two edits has no suggestion either
	// way, and a near miss still resolves.
	modeled := map[string]string{"alpha": "alpha"}
	if got, ok := suggestPolicyKey(strings.Repeat("a", 4096), modeled); ok {
		t.Errorf("suggestPolicyKey = %q, %t; want no suggestion for an oversized key", got, ok)
	}
	if got, ok := suggestPolicyKey("alpa", modeled); !ok || got != "alpha" {
		t.Errorf("suggestPolicyKey = %q, %t; want alpha, true", got, ok)
	}
}

func TestSuggestPolicyKeyIsDeterministic(t *testing.T) {
	t.Parallel()
	modeled := map[string]string{
		"alpha": "alpha",
		"alphi": "alphi",
	}
	if got, ok := suggestPolicyKey("alph", modeled); !ok || got != "alpha" {
		t.Fatalf("suggestPolicyKey = %q, %t; want alpha, true", got, ok)
	}
	if got, ok := suggestPolicyKey("unrelated", modeled); ok || got != "" {
		t.Fatalf("suggestPolicyKey = %q, %t; want empty, false", got, ok)
	}
}

func TestLevenshteinDistanceUsesRunes(t *testing.T) {
	t.Parallel()
	if got := levenshteinDistance("café", "cafe"); got != 1 {
		t.Fatalf("levenshteinDistance = %d, want 1", got)
	}
}
