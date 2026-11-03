//go:build live_verify

package alpha_test

import (
	"context"
	"os"
	"testing"

	tailscale "tailscale.com/client/tailscale/v2"

	"github.com/rshade/tail-acl/pkg/policycore/alpha"
)

// TestLiveVerifyRegisteredFeatures is the opt-in, credentialed smoke test for
// policycore/alpha's live-verify mechanism. The live_verify build tag keeps
// it out of every ordinary `go test ./...`, so no stray environment variable
// can make it run by accident — it is invoked deliberately, e.g.
//
//	go test -tags live_verify ./... -run TestLiveVerify -v
//
// by .github/workflows/alpha-live-verify.yml's opt-in workflow_dispatch job,
// which is the only place TAILSCALE_API_KEY and TAILSCALE_TAILNET are set for
// this test. It carries zero feature-specific knowledge: it seeds a
// VerifierRegistry from alpha.RepositoryFeatures() but imports no feature
// package and registers no LiveVerifyFunc of its own. There is no automatic
// verifier discovery. A feature-specific live_verify-tagged test must
// explicitly register and run the LiveVerifyFunc that lives with its
// hand-modeled types (see policycore/README.md's "Live-verifying an alpha
// feature" section). This generic test demonstrates only that live credentials
// resolve and the empty runner executes cleanly end to end.
func TestLiveVerifyRegisteredFeatures(t *testing.T) {
	t.Parallel()

	apiKey := os.Getenv("TAILSCALE_API_KEY")
	tailnet := os.Getenv("TAILSCALE_TAILNET")
	if apiKey == "" || tailnet == "" {
		t.Skip("TAILSCALE_API_KEY and TAILSCALE_TAILNET are required; this test is opt-in and credentialed")
	}

	ctx := context.Background()
	client := &tailscale.Client{APIKey: apiKey, Tailnet: tailnet}

	// Proves the credentials actually authenticate against the live API,
	// independent of whether any feature has registered a live verifier yet.
	if _, err := client.Devices().List(ctx); err != nil {
		t.Fatalf("Devices().List() = %v, want nil (credentials did not resolve)", err)
	}

	features := alpha.NewRegistry()
	for _, f := range alpha.RepositoryFeatures() {
		if err := features.Register(f); err != nil {
			t.Fatalf("Register(%q) = %v, want nil", f.Name, err)
		}
	}

	verifiers := alpha.NewVerifierRegistry(features)
	results := verifiers.RunAll(ctx)
	if len(results) == 0 {
		t.Log("no alpha feature currently registers a live verifier; " +
			"live-verify plumbing ran cleanly with nothing to check")
	}
	for _, r := range results {
		if r.Err != nil {
			t.Errorf("live-verify %q: %v", r.FeatureName, r.Err)
		}
	}
}
