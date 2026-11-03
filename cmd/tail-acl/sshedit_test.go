package main

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/rshade/tail-acl/internal/aclpolicy"
)

func TestSSHCommandsPreserveExtensionsAndComment(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.hujson")
	writeTestPolicy(t, path, `{
		"ssh": [{
			"action": "accept", "src": ["tag:workstations"],
			"dst": ["tag:servers"], "users": ["root"],
			"acceptEnv": ["LANG", "LC_*"]
		}],
		"sshTests": [{"src": "alice@example.com", "dst": ["tag:servers"], "accept": ["root"]}],
	}`)
	if _, err := runTailACL(t, path, "ssh", "add", "--action", "check",
		"--src", "autogroup:member", "--dst", "tag:servers", "--user", "root",
		"--check-period", "12h", "--comment", "reviewed"); err != nil {
		t.Fatal(err)
	}
	got := readPolicy(t, path)
	for _, want := range []string{`"acceptEnv": ["LANG", "LC_*"]`, `"sshTests": [`, "// reviewed"} {
		if !strings.Contains(got, want) {
			t.Errorf("ssh add lost %q:\n%s", want, got)
		}
	}
	comments, err := aclpolicy.LeadingComments(path, "ssh", "1")
	if err != nil || len(comments) != 1 || comments[0] != "reviewed" {
		t.Errorf("SSH comment = %q, %v; policy:\n%s", comments, err, got)
	}

	first := got
	if _, err = runTailACL(t, path, "ssh", "add", "--action", "check",
		"--src", "autogroup:member", "--dst", "tag:servers", "--user", "root",
		"--check-period", "12h", "--comment", "reviewed"); err != nil {
		t.Fatal(err)
	}
	if second := readPolicy(t, path); second != first {
		t.Errorf("idempotent ssh add changed policy:\n%s", second)
	}

	if _, err = runTailACL(t, path, "ssh", "remove", "--action", "check",
		"--src", "autogroup:member", "--dst", "tag:servers", "--user", "root",
		"--check-period", "12h"); err != nil {
		t.Fatal(err)
	}
	policy, err := aclpolicy.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(policy.SSH) != 1 || len(policy.SSHTests) != 1 || len(policy.SSH[0].AcceptEnv) != 2 {
		t.Errorf("remove damaged preserved SSH data: SSH=%#v SSHTests=%#v", policy.SSH, policy.SSHTests)
	}
}

func TestSSHHelpAndSchemaExposeSemantics(t *testing.T) {
	t.Parallel()
	for _, args := range [][]string{{"ssh", "add", "--help"}, {"ssh", "remove", "--help"}} {
		stdout, err := runTailACL(t, "acl.json", args...)
		if err != nil {
			t.Errorf("run(%q): %v", args, err)
			continue
		}
		for _, want := range []string{"accept", "check", "check-period", "always"} {
			if !strings.Contains(stdout, want) {
				t.Errorf("help %q lacks %q:\n%s", args, want, stdout)
			}
		}
	}
	stdout, err := runTailACL(t, "acl.json", "-schema")
	if err != nil {
		t.Fatal(err)
	}
	for _, command := range []string{commandSSHAdd, commandSSHRemove} {
		if !strings.Contains(stdout, `"name": "`+command+`"`) {
			t.Errorf("schema lacks %q", command)
		}
	}
	if !strings.Contains(stdout, "check without a period differs from check with one") {
		t.Error("schema does not document checkPeriod identity semantics")
	}
}
