package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rshade/tail-acl/internal/aclpolicy"
	"github.com/rshade/tail-acl/pkg/policycore/sanitize"
	"github.com/rshade/tail-acl/pkg/policycore/sanitize/sanitizetest"
)

func TestExternalTailnetAddPreservesCommentAndRepeats(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.hujson")
	const original = `{
	// keep the grant comment
	"grants": [],
}
`
	writeTestPolicy(t, path, original)
	if _, err := runTailACL(t, path,
		"external-tailnet", "add", "partner", "--external-id", "tn-123", "--allow-incoming",
	); err != nil {
		t.Fatal(err)
	}
	updated := readPolicy(t, path)
	if !strings.Contains(updated, "// keep the grant comment") {
		t.Fatalf("comment lost:\n%s", updated)
	}
	loaded, err := aclpolicy.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	declaration, ok := loaded.ExternalTailnets["partner"]
	if !ok || declaration.ExternalID != "tn-123" || !declaration.AllowIncomingConnections {
		t.Fatalf("alias = %+v, present=%t", declaration, ok)
	}
	afterFirst := readPolicy(t, path)
	if _, err = runTailACL(t, path,
		"external-tailnet", "add", "partner", "--external-id", "tn-123", "--allow-incoming",
	); err != nil {
		t.Fatal(err)
	}
	if got := readPolicy(t, path); got != afterFirst {
		t.Fatalf("repeat changed the file\n got:\n%s\nwant:\n%s", got, afterFirst)
	}
	goldenPath := filepath.Join("testdata", "external_tailnet_add.golden.hujson")
	want, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatal(err)
	}
	if afterFirst != string(want) {
		t.Errorf("golden mismatch\n got:\n%s\nwant:\n%s", afterFirst, want)
	}
}

func TestExternalTailnetRemovePreservesComment(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.hujson")
	writeTestPolicy(t, path, `{
	// keep the grant comment
	"grants": [],
	"externalTailnets": {
		"partner": {"externalID": "tn-123"},
	},
}
`)
	if _, err := runTailACL(t, path, "external-tailnet", "remove", "partner"); err != nil {
		t.Fatal(err)
	}
	got := readPolicy(t, path)
	if !strings.Contains(got, "// keep the grant comment") {
		t.Fatalf("comment lost:\n%s", got)
	}
	goldenPath := filepath.Join("testdata", "external_tailnet_remove.golden.hujson")
	want, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatal(err)
	}
	if got != string(want) {
		t.Errorf("golden mismatch\n got:\n%s\nwant:\n%s", got, want)
	}
}

func TestExternalTailnetListJSONIsEmptyWhenSectionIsAbsent(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.hujson")
	writeTestPolicy(t, path, `{
	"grants": [],
}
`)
	raw, err := runTailACL(t, path, "-format", "json", "external-tailnet", "list")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(raw, "\"external_tailnets\": []") {
		t.Fatalf("json = %s", raw)
	}
	var envelope struct {
		ExternalTailnets []aclpolicy.ExternalTailnetEntry `json:"external_tailnets"`
	}
	if err = json.Unmarshal([]byte(raw), &envelope); err != nil {
		t.Fatalf("json: %v\n%s", err, raw)
	}
	if envelope.ExternalTailnets == nil || len(envelope.ExternalTailnets) != 0 {
		t.Fatalf("entries = %#v", envelope.ExternalTailnets)
	}
}

func TestExternalTailnetRemoveRefusesThenForces(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.hujson")
	writeTestPolicy(t, path, `{
	"externalTailnets": {"partner": {"externalID": "tn-123"}},
	"grants": [{"src": ["group://partner/eng"], "dst": ["autogroup:self"], "ip": ["*"]}]
}
`)
	_, err := runTailACL(t, path, "external-tailnet", "remove", "partner")
	if err == nil || exitCode(err) == exitUsage {
		t.Fatalf("remove error = %v, want a failed removal", err)
	}
	if !strings.Contains(err.Error(), "grants[0].src[0]") {
		t.Errorf("error = %v", err)
	}
	loaded, loadErr := aclpolicy.Load(path)
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	if _, ok := loaded.ExternalTailnets["partner"]; !ok {
		t.Fatal("alias was removed without --force")
	}
	if _, err = runTailACL(t, path, "external-tailnet", "remove", "partner", "--force"); err != nil {
		t.Fatal(err)
	}
	loaded, err = aclpolicy.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := loaded.ExternalTailnets["partner"]; ok {
		t.Fatal("alias still present after --force")
	}
}

func TestExternalTailnetRemoveRejectsInvalidAliasAsUsage(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.hujson")
	const original = `{
	"externalTailnets": {"partner": {"externalID": "tn-123"}},
}
`
	writeTestPolicy(t, path, original)
	_, err := runTailACL(t, path, "external-tailnet", "remove", "bad/alias")
	if exitCode(err) != exitUsage {
		t.Fatalf("remove error = %v, exit = %d, want %d", err, exitCode(err), exitUsage)
	}
	if got := readPolicy(t, path); got != original {
		t.Fatalf("invalid alias changed the file:\n%s", got)
	}
}

func TestExternalTailnetMutationsSanitizeAlias(t *testing.T) {
	t.Parallel()
	const alias = "SensitivePartner"
	const declared = `{
	"externalTailnets": {"SensitivePartner": {"externalID": "tn-123"}},
}
`
	const absent = `{
	"grants": [],
}
`
	addArgs := []string{"external-tailnet", "add", alias, "--external-id", "tn-123"}
	removeArgs := []string{"external-tailnet", "remove", alias}
	for _, testCase := range []struct {
		name   string
		policy string
		args   []string
		status string
	}{
		{name: "add", policy: absent, args: addArgs, status: statusOK},
		{name: "add no-op", policy: declared, args: addArgs, status: statusNoChanges},
		{name: "remove", policy: declared, args: removeArgs, status: statusOK},
		{name: "remove no-op", policy: absent, args: removeArgs, status: statusNoChanges},
	} {
		for _, variant := range []struct {
			level  sanitize.Level
			format string
		}{
			{sanitize.Identity, formatJSON},
			{sanitize.Identity, formatHuman},
			{sanitize.Strict, formatJSON},
			{sanitize.Strict, formatHuman},
		} {
			t.Run(testCase.name+"/"+string(variant.level)+"/"+variant.format, func(t *testing.T) {
				t.Parallel()
				path := filepath.Join(t.TempDir(), "acl.hujson")
				writeTestPolicy(t, path, testCase.policy)
				args := append(
					[]string{"--sanitize", string(variant.level), "-format", variant.format},
					testCase.args...,
				)
				stdout, err := runTailACL(t, path, args...)
				if err != nil {
					t.Fatal(err)
				}
				if variant.format == formatJSON && decodeStatus(t, stdout) != testCase.status {
					t.Fatalf("status = %q, want %q", decodeStatus(t, stdout), testCase.status)
				}
				sanitizetest.AssertNoIdentityLeaks(t, []byte(stdout), []string{alias})
			})
		}
	}
}

func TestExternalTailnetListHumanAndJSON(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.hujson")
	writeTestPolicy(t, path, `{
	"externalTailnets": {"partner": {"externalID": "tn-123", "allowIncomingConnections": true}}
}
`)
	human, err := runTailACL(t, path, "external-tailnet", "list")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(human, "partner") || !strings.Contains(human, "allowIncomingConnections=true") {
		t.Errorf("human = %q", human)
	}
	raw, err := runTailACL(t, path, "-format", "json", "external-tailnet", "list")
	if err != nil {
		t.Fatal(err)
	}
	var envelope struct {
		ExternalTailnets []aclpolicy.ExternalTailnetEntry `json:"external_tailnets"`
	}
	if err = json.Unmarshal([]byte(raw), &envelope); err != nil {
		t.Fatalf("json: %v\n%s", err, raw)
	}
	if len(envelope.ExternalTailnets) != 1 || envelope.ExternalTailnets[0].Alias != "partner" {
		t.Fatalf("entries = %+v", envelope.ExternalTailnets)
	}
}
