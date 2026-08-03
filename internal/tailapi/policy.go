// Package tailapi provides shared access to Tailscale's policy-file API.
package tailapi

import (
	"context"
	"fmt"
	"net/http"
	"net/url"

	diff "github.com/hexops/gotextdiff"
	"github.com/hexops/gotextdiff/myers"
	"github.com/hexops/gotextdiff/span"
	"github.com/tailscale/hujson"
	tailscale "tailscale.com/client/tailscale/v2"

	"github.com/rshade/tailscale-utils/tail-acl/internal/aclpolicy"
)

const DefaultBaseURL = "https://api.tailscale.com"

// Config configures the official Tailscale v2 API client.
type Config struct {
	APIKey  string
	Tailnet string
	BaseURL string
	HTTP    *http.Client
}

// Plan describes the validated difference between the deployed policy and a
// local candidate. ETag identifies the deployed version used for the diff.
type Plan struct {
	Diff       string
	ETag       string
	Changed    bool
	Validation ValidationResult
}

// NewClient constructs the official Tailscale API client.
func NewClient(config Config) (*tailscale.Client, error) {
	baseURL := config.BaseURL
	if baseURL == "" {
		baseURL = DefaultBaseURL
	}
	parsed, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("parsing Tailscale API URL: %w", err)
	}
	return &tailscale.Client{
		APIKey:  config.APIKey,
		Tailnet: config.Tailnet,
		BaseURL: parsed,
		HTTP:    config.HTTP,
	}, nil
}

// UploadFile validates path as HuJSON and sets it as the tailnet policy.
func UploadFile(ctx context.Context, client *tailscale.Client, path, ifMatch string) error {
	raw, err := aclpolicy.ReadRaw(path)
	if err != nil {
		return err
	}
	if err = client.PolicyFile().Set(ctx, string(raw), ifMatch); err != nil {
		return fmt.Errorf("uploading %s: %w", path, err)
	}
	return nil
}

// ValidateFile asks Tailscale to validate the policy and run its policy tests.
func ValidateFile(ctx context.Context, client *tailscale.Client, path string) (ValidationResult, error) {
	raw, err := aclpolicy.ReadRaw(path)
	if err != nil {
		return newValidationResult(), err
	}
	result, err := ValidatePolicy(ctx, client, raw)
	if err != nil {
		return result, fmt.Errorf("validating %s: %w", path, err)
	}
	return result, nil
}

// PlanFile fetches the deployed policy, validates path without applying it,
// and returns a formatted unified diff from deployed to candidate policy.
//
// Once validation has run, every failure returns a non-nil *Plan carrying only
// Validation — Diff, ETag, and Changed stay zero — so a caller can still report
// the per-user detail and any warnings the control plane did supply rather than
// discarding diagnostics it already collected. A caller must therefore check
// the error before reading Changed, which otherwise reads as a confident "no
// changes" for a candidate that was never diffed. Validation verdicts wrap
// [ValidationError] or [ValidationIndeterminateError]; every failure before
// validation returns a nil *Plan.
func PlanFile(ctx context.Context, client *tailscale.Client, path string) (*Plan, error) {
	candidate, err := aclpolicy.ReadRaw(path)
	if err != nil {
		return nil, err
	}

	deployed, err := client.PolicyFile().Raw(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetching deployed policy: %w", err)
	}
	validation, err := ValidatePolicy(ctx, client, candidate)
	if err != nil {
		if ClassifyValidation(err).Judged() {
			return &Plan{Validation: validation}, fmt.Errorf("validating %s: %w", path, err)
		}
		return nil, fmt.Errorf("validating %s: %w", path, err)
	}

	deployedFormatted, err := hujson.Format([]byte(deployed.HuJSON))
	if err != nil {
		return &Plan{Validation: validation}, fmt.Errorf("formatting deployed policy: %w", err)
	}
	candidateFormatted, err := hujson.Format(candidate)
	if err != nil {
		return &Plan{Validation: validation}, fmt.Errorf("formatting %s: %w", path, err)
	}

	before := string(deployedFormatted)
	edits := myers.ComputeEdits(span.URIFromPath(path), before, string(candidateFormatted))
	unified := diff.ToUnified("deployed", path, before, edits)
	return &Plan{
		Diff:       fmt.Sprint(unified),
		ETag:       deployed.ETag,
		Changed:    len(edits) != 0,
		Validation: validation,
	}, nil
}
