package alpha_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/rshade/tail-acl/pkg/policycore/alpha"
)

var errRequiredFieldMissing = errors.New(
	"live response is missing requiredField: hand-modeled type no longer matches the API",
)

func registeredFeatures(t *testing.T, names ...string) *alpha.Registry {
	t.Helper()

	registry := alpha.NewRegistry()
	for _, name := range names {
		feature := alpha.Feature{
			Name:        name,
			DocURL:      "https://tailscale.com/kb/" + name,
			ModeledDate: time.Date(2026, time.August, 28, 0, 0, 0, 0, time.UTC),
			Stage:       alpha.StageAlpha,
		}
		if err := registry.Register(feature); err != nil {
			t.Fatalf("Register(%q) = %v, want nil", name, err)
		}
	}
	return registry
}

func TestVerifierRegistryRegisterRejectsUnknownFeature(t *testing.T) {
	t.Parallel()

	registry := alpha.NewVerifierRegistry(registeredFeatures(t))
	err := registry.RegisterVerifier("does-not-exist", func(context.Context) error { return nil })
	if err == nil {
		t.Fatal("RegisterVerifier() = nil, want error")
	}
}

func TestVerifierRegistryRegisterRejectsNilFunc(t *testing.T) {
	t.Parallel()

	registry := alpha.NewVerifierRegistry(registeredFeatures(t, "feature-a"))
	err := registry.RegisterVerifier("feature-a", nil)
	if err == nil {
		t.Fatal("RegisterVerifier() = nil, want error")
	}
}

func TestVerifierRegistryRegisterRejectsDuplicate(t *testing.T) {
	t.Parallel()

	registry := alpha.NewVerifierRegistry(registeredFeatures(t, "feature-a"))
	if err := registry.RegisterVerifier("feature-a", func(context.Context) error { return nil }); err != nil {
		t.Fatalf("first RegisterVerifier() = %v, want nil", err)
	}
	if err := registry.RegisterVerifier("feature-a", func(context.Context) error { return nil }); err == nil {
		t.Fatal("second RegisterVerifier() = nil, want error")
	}
}

// stubFeaturePayload stands in for a hand-modeled alpha feature's type: a
// live-verify function decodes the live response into it and fails when a
// field the type expects is missing, the way real schema drift would surface.
type stubFeaturePayload struct {
	RequiredField string `json:"requiredField"`
}

func verifyAgainstServer(url string) alpha.LiveVerifyFunc {
	return func(ctx context.Context) error {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return err
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		var payload stubFeaturePayload
		if decodeErr := json.NewDecoder(resp.Body).Decode(&payload); decodeErr != nil {
			return decodeErr
		}
		if payload.RequiredField == "" {
			return errRequiredFieldMissing
		}
		return nil
	}
}

// TestVerifierRegistryRunAllReportsPerFeatureResults proves the mechanism
// this issue exists to build: verifying a hand-modeled type against a live
// API response is testable with a local stub, no real credentials required.
// One server serves the shape the hand-modeled type expects; the other
// simulates schema drift by omitting the field.
func TestVerifierRegistryRunAllReportsPerFeatureResults(t *testing.T) {
	t.Parallel()

	matching := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(stubFeaturePayload{RequiredField: "present"})
	}))
	defer matching.Close()

	drifted := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(struct{}{})
	}))
	defer drifted.Close()

	registry := alpha.NewVerifierRegistry(registeredFeatures(t, "feature-ok", "feature-drifted"))
	if err := registry.RegisterVerifier("feature-ok", verifyAgainstServer(matching.URL)); err != nil {
		t.Fatalf("RegisterVerifier(feature-ok) = %v, want nil", err)
	}
	if err := registry.RegisterVerifier("feature-drifted", verifyAgainstServer(drifted.URL)); err != nil {
		t.Fatalf("RegisterVerifier(feature-drifted) = %v, want nil", err)
	}

	results := registry.RunAll(context.Background())
	if len(results) != 2 {
		t.Fatalf("RunAll() returned %d results, want 2", len(results))
	}

	if results[0].FeatureName != "feature-drifted" || results[1].FeatureName != "feature-ok" {
		t.Fatalf("RunAll() results not sorted by FeatureName: got %q, %q",
			results[0].FeatureName, results[1].FeatureName)
	}
	if results[0].Err == nil {
		t.Error("feature-drifted result Err = nil, want an error reporting the missing field")
	}
	if results[1].Err != nil {
		t.Errorf("feature-ok result Err = %v, want nil", results[1].Err)
	}
}
