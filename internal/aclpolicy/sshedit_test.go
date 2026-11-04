package aclpolicy_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rshade/tsacl/internal/aclpolicy"
)

const sshEditPolicy = `{
	// Keep the file's syntax while adding an SSH rule.
	"ssh": [
		{
			"action": "accept",
			"src": ["tag:workstations"],
			"dst": ["tag:servers"],
			"users": ["root"],
			"acceptEnv": ["LANG", "LC_*"]
		},
	],
	"sshTests": [
		{"src": "alice@example.com", "dst": ["tag:servers"], "accept": ["root"]},
	],
}
`

func TestSSHAddPreservesAcceptEnvAndSSHTests(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.hujson")
	if err := os.WriteFile(path, []byte(sshEditPolicy), 0o600); err != nil {
		t.Fatal(err)
	}
	policy, err := aclpolicy.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	edit, err := aclpolicy.AddSSHRule(policy, aclpolicy.SSHRuleSpec{
		Action: "check", Source: []string{"autogroup:member"},
		Destination: []string{"tag:servers"}, Users: []string{"root"},
		CheckPeriod: "12h", CheckPeriodSet: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = aclpolicy.WritePatch(path, edit.Operations...); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), `"acceptEnv": ["LANG", "LC_*"]`) {
		t.Errorf("acceptEnv was lost:\n%s", got)
	}
	if !strings.Contains(string(got), `"sshTests": [`) {
		t.Errorf("sshTests were lost:\n%s", got)
	}
	if !strings.Contains(string(got), "Keep the file's syntax") {
		t.Errorf("existing comment was lost:\n%s", got)
	}
	if _, err = aclpolicy.Load(path); err != nil {
		t.Fatalf("edited policy no longer loads: %v\n%s", err, got)
	}
}

func TestSSHAddIsOrderInsensitiveAndIdempotent(t *testing.T) {
	t.Parallel()
	policy, err := aclpolicy.LoadBytes("test.hujson", []byte(`{"ssh": [{
		"action": "check", "src": ["tag:workstations", "group:ops"],
		"dst": ["tag:servers", "host:jump"], "users": ["root", "ubuntu"],
		"checkPeriod": "12h"
	}]}`))
	if err != nil {
		t.Fatal(err)
	}
	edit, err := aclpolicy.AddSSHRule(policy, aclpolicy.SSHRuleSpec{
		Action: "check", Source: []string{"group:ops", "tag:workstations"},
		Destination: []string{"host:jump", "tag:servers"}, Users: []string{"ubuntu", "root"},
		CheckPeriod: "12h", CheckPeriodSet: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if edit.Changed() || edit.RuleIndex != 0 {
		t.Fatalf("reordered SSH add = %#v, want no changes at index 0", edit)
	}
}

func TestSSHCheckPeriodPresenceIsPartOfIdentity(t *testing.T) {
	t.Parallel()
	policy, err := aclpolicy.LoadBytes("test.hujson", []byte(`{"ssh": [
		{"action": "check", "src": ["*"], "dst": ["tag:server"], "users": ["root"]}
	]}`))
	if err != nil {
		t.Fatal(err)
	}
	edit, err := aclpolicy.AddSSHRule(policy, aclpolicy.SSHRuleSpec{
		Action: "check", Source: []string{"*"}, Destination: []string{"tag:server"},
		Users: []string{"root"}, CheckPeriod: "12h", CheckPeriodSet: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !edit.Changed() || edit.RuleIndex != 1 {
		t.Fatalf("perioded check add = %#v, want a second rule", edit)
	}
}

func TestSSHRemoveRoundTripsAddedRule(t *testing.T) {
	t.Parallel()
	original := `{"ssh": [{
	"action": "accept",
	"src":    ["*"],
	"dst":    ["tag:server"],
	"users":  ["root"]
}]}
`
	path := filepath.Join(t.TempDir(), "acl.json")
	if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	policy, err := aclpolicy.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	add, err := aclpolicy.AddSSHRule(policy, aclpolicy.SSHRuleSpec{
		Action: "check", Source: []string{"*"}, Destination: []string{"tag:server"},
		Users: []string{"root"}, CheckPeriod: "12h", CheckPeriodSet: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = aclpolicy.WritePatch(path, add.Operations...); err != nil {
		t.Fatal(err)
	}
	policy, err = aclpolicy.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	remove, err := aclpolicy.RemoveSSHRule(policy, aclpolicy.SSHRuleSpec{
		Action: "check", Source: []string{"*"}, Destination: []string{"tag:server"},
		Users: []string{"root"}, CheckPeriod: "12h", CheckPeriodSet: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = aclpolicy.WritePatch(path, remove.Operations...); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != original {
		t.Errorf("add then remove did not round-trip bytes:\ngot:  %q\nwant: %q", got, original)
	}
}

// TestSSHCheckPeriodRejectsNonPositive pins both halves of the guard. -1ns is
// the tailscale.CheckPeriodAlways sentinel, so accepting it wrote back a
// stricter rule than the operator requested; any other non-positive value was
// written back verbatim as a period nobody can have meant.
func TestSSHCheckPeriodRejectsNonPositive(t *testing.T) {
	t.Parallel()
	spec := func(period string) aclpolicy.SSHRuleSpec {
		return aclpolicy.SSHRuleSpec{
			Action: "check", Source: []string{"*"}, Destination: []string{"tag:server"},
			Users: []string{"root"}, CheckPeriod: period, CheckPeriodSet: true,
		}
	}
	for _, period := range []string{"-5m", "-1ns", "0s"} {
		t.Run("rejects "+period, func(t *testing.T) {
			t.Parallel()
			policy, err := aclpolicy.LoadBytes("test.hujson", []byte(`{}`))
			if err != nil {
				t.Fatal(err)
			}
			if _, err = aclpolicy.AddSSHRule(policy, spec(period)); err == nil {
				t.Errorf("check period %q was accepted", period)
			}
		})
	}
	for _, period := range []string{"always", "12h"} {
		t.Run("accepts "+period, func(t *testing.T) {
			t.Parallel()
			policy, err := aclpolicy.LoadBytes("test.hujson", []byte(`{}`))
			if err != nil {
				t.Fatal(err)
			}
			edit, err := aclpolicy.AddSSHRule(policy, spec(period))
			if err != nil || !edit.Changed() {
				t.Errorf("check period %q = %#v, %v; want an edit", period, edit, err)
			}
		})
	}
}
