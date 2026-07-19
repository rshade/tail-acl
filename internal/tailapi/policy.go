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
	Diff    string
	ETag    string
	Changed bool
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
func ValidateFile(ctx context.Context, client *tailscale.Client, path string) error {
	raw, err := aclpolicy.ReadRaw(path)
	if err != nil {
		return err
	}
	if err = client.PolicyFile().Validate(ctx, string(raw)); err != nil {
		return fmt.Errorf("validating %s: %w", path, err)
	}
	return nil
}

// PlanFile fetches the deployed policy, validates path without applying it,
// and returns a formatted unified diff from deployed to candidate policy.
func PlanFile(ctx context.Context, client *tailscale.Client, path string) (*Plan, error) {
	candidate, err := aclpolicy.ReadRaw(path)
	if err != nil {
		return nil, err
	}

	deployed, err := client.PolicyFile().Raw(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetching deployed policy: %w", err)
	}
	if err = client.PolicyFile().Validate(ctx, string(candidate)); err != nil {
		return nil, fmt.Errorf("validating %s: %w", path, err)
	}

	deployedFormatted, err := hujson.Format([]byte(deployed.HuJSON))
	if err != nil {
		return nil, fmt.Errorf("formatting deployed policy: %w", err)
	}
	candidateFormatted, err := hujson.Format(candidate)
	if err != nil {
		return nil, fmt.Errorf("formatting %s: %w", path, err)
	}

	before := string(deployedFormatted)
	edits := myers.ComputeEdits(span.URIFromPath(path), before, string(candidateFormatted))
	unified := diff.ToUnified("deployed", path, before, edits)
	return &Plan{
		Diff:    fmt.Sprint(unified),
		ETag:    deployed.ETag,
		Changed: len(edits) != 0,
	}, nil
}
