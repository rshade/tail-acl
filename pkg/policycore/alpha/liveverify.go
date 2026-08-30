package alpha

import (
	"context"
	"fmt"
	"slices"
)

// LiveVerifyFunc exercises one hand-modeled alpha feature against a real,
// live tailnet and reports a non-nil error when the feature's hand-modeled
// type no longer matches what the live API actually returns. It takes only
// ctx: the credentials and client it needs to make that call are the
// registering caller's to close over, so this package never depends on how a
// feature talks to the live API.
type LiveVerifyFunc func(ctx context.Context) error

// VerifyResult is one feature's live-verify outcome.
type VerifyResult struct {
	FeatureName string
	Err         error
}

// VerifierRegistry is a caller-owned collection of LiveVerifyFuncs, each tied
// to a Feature name already present in a backing Registry. It is a separate
// type from Registry, not a field on Feature, because a LiveVerifyFunc closes
// over live credentials and is not comparable — bundling it onto Feature
// would break Feature's use as plain, comparable inventory data.
type VerifierRegistry struct {
	features  *Registry
	verifiers map[string]LiveVerifyFunc
}

// NewVerifierRegistry returns an empty VerifierRegistry backed by features.
// RegisterVerifier rejects a feature name that features does not already have
// registered, so features must be populated first.
func NewVerifierRegistry(features *Registry) *VerifierRegistry {
	return &VerifierRegistry{features: features, verifiers: make(map[string]LiveVerifyFunc)}
}

// RegisterVerifier ties verify to featureName. It rejects a nil verify, a
// featureName not already present in the backing Registry — a live-verify
// function for an unregistered feature is either a typo or dead code — and a
// featureName that already carries a verifier.
func (vr *VerifierRegistry) RegisterVerifier(featureName string, verify LiveVerifyFunc) error {
	if verify == nil {
		return fmt.Errorf("alpha: live verifier for %q: verify function is required", featureName)
	}
	if _, ok := vr.features.Lookup(featureName); !ok {
		return fmt.Errorf("alpha: live verifier for %q: not a registered feature", featureName)
	}
	if _, exists := vr.verifiers[featureName]; exists {
		return fmt.Errorf("alpha: live verifier for %q is already registered", featureName)
	}
	vr.verifiers[featureName] = verify
	return nil
}

// RunAll runs every registered LiveVerifyFunc against ctx and returns one
// VerifyResult per verifier, sorted by FeatureName so a caller's output is
// deterministic. It does not stop at the first failure: schema drift in one
// feature should not hide drift in another.
func (vr *VerifierRegistry) RunAll(ctx context.Context) []VerifyResult {
	names := make([]string, 0, len(vr.verifiers))
	for name := range vr.verifiers {
		names = append(names, name)
	}
	slices.Sort(names)

	results := make([]VerifyResult, 0, len(names))
	for _, name := range names {
		results = append(results, VerifyResult{FeatureName: name, Err: vr.verifiers[name](ctx)})
	}
	return results
}
