// Package alpha is the shared convention for hand-modeling a Tailscale
// feature that is alpha or unreleased in the pinned
// tailscale.com/client/tailscale/v2 SDK, so a tool in this repo can pick up
// an alpha feature early instead of waiting for the SDK to catch up.
//
// It owns the Registry, which validates and queries a
// caller-owned feature inventory; RepositoryFeatures, the canonical inventory
// of every feature this repository hand-models (Name, DocURL, ModeledDate, and
// pipeline Stage); and AlphaHint, the string "alpha-hint" and the third
// SourceRef confidence value alongside "derived" and "hint" (AGENTS.md AX
// convention 13). A hint is editorial evidence verified against a stable
// pinned module; AlphaHint is editorial evidence against a surface Tailscale
// itself calls unstable — categorically weaker.
//
// Shared hand-modeled policy syntax can also live here when more than one
// tool needs an identical representation; the declarative node-sharing
// selector grammar is the first. Its relationship data was hand-modeled here
// too, until tailscale.com/client/tailscale/v2 v2.11.0 grew a real
// externalTailnets field and the migration tripwire moved the model onto the
// SDK's type.
// Each feature is expected to carry its own migration tripwire — a test that
// fails once the pinned SDK adds real support for the feature, forcing a
// conscious decision to migrate off the hand-modeled types rather than letting
// them silently diverge from the now-real SDK types.
// RepositoryFeatures makes the feature discoverable; it does not enforce that
// feature's tripwire itself.
package alpha

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

// AlphaHint is the string "alpha-hint": the source-provenance confidence tier
// for data derived from a Tailscale feature this repo has hand-modeled ahead
// of the pinned SDK. It is deliberately its own SourceRef value, not folded
// into "hint": a hint describes evidence against a stable pinned module,
// while AlphaHint describes evidence against a surface Tailscale itself calls
// unstable.
const AlphaHint = "alpha-hint"

// Stage is a hand-modeled feature's position in Tailscale's own release
// pipeline.
type Stage string

const (
	StageAlpha Stage = "alpha"
	StageBeta  Stage = "beta"
	StageGA    Stage = "ga"
)

func (s Stage) valid() bool {
	switch s {
	case StageAlpha, StageBeta, StageGA:
		return true
	default:
		return false
	}
}

// Feature is one hand-modeled Tailscale alpha feature: what it is, where its
// spec comes from, when this repo started modeling it, and how far it has
// moved through Tailscale's own release pipeline.
type Feature struct {
	Name        string
	DocURL      string
	ModeledDate time.Time
	Stage       Stage
}

// RepositoryFeatures returns the canonical repository-wide feature inventory.
// Add every hand-modeled alpha or unreleased feature to the slice returned
// here. A fresh slice is returned on every call, so callers cannot mutate the
// inventory exposed to the rest of the repository.
func RepositoryFeatures() []Feature {
	return []Feature{
		{
			Name:        "declarative-node-sharing",
			DocURL:      "https://tailscale.com/docs/features/declarative-node-sharing",
			ModeledDate: time.Date(2026, time.September, 3, 0, 0, 0, 0, time.UTC),
			Stage:       StageAlpha,
		},
	}
}

// Registry validates and queries a caller-owned feature inventory. It is not
// shared package state; registering a feature does not update the canonical
// inventory returned by RepositoryFeatures.
type Registry struct {
	features map[string]Feature
}

// NewRegistry returns an empty, caller-owned Registry.
func NewRegistry() *Registry {
	return &Registry{features: make(map[string]Feature)}
}

// Register adds f to the registry. It rejects a Feature missing a required
// field, an unrecognized Stage, and a Name already registered — the same
// fail-loud posture sanitize.ParseLevel uses for an unrecognized Level.
func (r *Registry) Register(f Feature) error {
	switch {
	case f.Name == "":
		return errors.New("alpha: feature name is required")
	case f.DocURL == "":
		return fmt.Errorf("alpha: feature %q: doc URL is required", f.Name)
	case f.ModeledDate.IsZero():
		return fmt.Errorf("alpha: feature %q: modeled date is required", f.Name)
	case !f.Stage.valid():
		return fmt.Errorf("alpha: feature %q: unknown stage %q; want alpha, beta, or ga", f.Name, f.Stage)
	}
	if _, exists := r.features[f.Name]; exists {
		return fmt.Errorf("alpha: feature %q is already registered", f.Name)
	}
	r.features[f.Name] = f
	return nil
}

// Lookup returns the Feature registered under name, if any.
func (r *Registry) Lookup(name string) (Feature, bool) {
	f, ok := r.features[name]
	return f, ok
}

// List returns every registered Feature, sorted by Name so the result is
// deterministic across the randomized map-iteration order Go uses internally.
func (r *Registry) List() []Feature {
	list := make([]Feature, 0, len(r.features))
	for _, f := range r.features {
		list = append(list, f)
	}
	slices.SortFunc(list, func(a, b Feature) int { return strings.Compare(a.Name, b.Name) })
	return list
}
