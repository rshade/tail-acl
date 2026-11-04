//go:build live_verify

package posture_test

import (
	"context"
	"os"
	"strings"
	"testing"

	tailscale "tailscale.com/client/tailscale/v2"
)

// TestLiveVerifyCountryVocabulary re-derives the ip:country vocabulary from
// the control plane and fails on drift. The live_verify build tag keeps it out
// of every ordinary `go test ./...`; it is invoked deliberately, e.g.
//
//	go test -tags live_verify ./pkg/policycore/posture/ -run TestLiveVerify -v
//
// with TAILSCALE_API_KEY and TAILSCALE_TAILNET set. It is read-only: /acl/validate
// checks a candidate and never saves it.
//
// The derivation mirrors how the fixture was captured on 2026-10-02: a policy
// whose posture lists an invalid country code is submitted to /acl/validate,
// and the server's rejection enumerates every code it accepts as "valid
// values: AD, AE, ...". That list is compared against the fixture — the
// source of truth — so a server-side vocabulary change fails here first
// rather than surfacing as a lint false positive. The client appends "; []" to
// the message, so the list ends at the first semicolon.
func TestLiveVerifyCountryVocabulary(t *testing.T) {
	t.Parallel()

	apiKey := os.Getenv("TAILSCALE_API_KEY")
	tailnet := os.Getenv("TAILSCALE_TAILNET")
	if apiKey == "" || tailnet == "" {
		t.Skip("TAILSCALE_API_KEY and TAILSCALE_TAILNET are required; this test is opt-in and credentialed")
	}

	client := &tailscale.Client{APIKey: apiKey, Tailnet: tailnet}
	// ZZ is deliberately the invalid probe value: it is outside the recorded
	// vocabulary, so a server that accepts it has changed in a way this test
	// exists to catch.
	const probe = `{"postures": {"posture:vocab-probe": ["ip:country NOT IN ['ZZ']"]}}`
	err := client.PolicyFile().Validate(context.Background(), probe)
	if err == nil {
		t.Fatal("the control plane accepted ip:country 'ZZ'; the recorded vocabulary is stale")
	}
	message := err.Error()
	const marker = "valid values: "
	_, rest, found := strings.Cut(message, marker)
	if !found {
		t.Fatalf("the validation error does not enumerate valid values; the server's "+
			"error shape changed: %s", message)
	}
	codeList, _, _ := strings.Cut(rest, ";")
	serverCodes := strings.Split(strings.TrimSpace(codeList), ", ")

	fixtureData, readErr := os.ReadFile("testdata/ip_country_vocabulary.txt")
	if readErr != nil {
		t.Fatalf("reading the country fixture: %v", readErr)
	}
	var fixtureCodes []string
	for line := range strings.Lines(string(fixtureData)) {
		code := strings.TrimSpace(line)
		if code == "" || strings.HasPrefix(code, "#") {
			continue
		}
		fixtureCodes = append(fixtureCodes, code)
	}

	server := make(map[string]bool, len(serverCodes))
	for _, code := range serverCodes {
		server[code] = true
	}
	fixture := make(map[string]bool, len(fixtureCodes))
	for _, code := range fixtureCodes {
		fixture[code] = true
	}
	for code := range server {
		if !fixture[code] {
			t.Errorf("the control plane now accepts %q, which the fixture does not list", code)
		}
	}
	for code := range fixture {
		if !server[code] {
			t.Errorf("the fixture lists %q, which the control plane no longer accepts", code)
		}
	}
}
