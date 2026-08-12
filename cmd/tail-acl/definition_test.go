package main

import (
	"context"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rshade/tailscale-utils/tail-acl/internal/aclpolicy"
)

func TestDefinitionCommandsCloseLintRoundTrip(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.hujson")
	writeTestPolicy(t, path, `{
		// Keep this comment while the typed editor changes the policy.
		"grants": [{"src": ["group:eng"], "dst": ["ipset:office"], "ip": ["tcp:443"]}],
		"tagOwners": {"tag:web": ["autogroup:admin"]},
	}`)

	initialLint, err := runTailACL(t, path, cmdLint)
	if err == nil || !strings.Contains(initialLint, `"id": "undefined-reference"`) {
		t.Fatalf("initial lint error = %v, want undefined references", err)
	}
	if _, addErr := runTailACL(t, path, cmdGroup, subAdd,
		"--name", "group:eng", "--member", "alice@example.com", "--comment", "Engineering"); addErr != nil {
		t.Fatal(addErr)
	}
	if _, ipsetErr := runTailACL(t, path, cmdIPSet, subAdd,
		"--name", "ipset:office", "--cidr", "10.0.0.0/8"); ipsetErr != nil {
		t.Fatal(ipsetErr)
	}
	if _, lintErr := runTailACL(t, path, cmdLint); lintErr != nil {
		t.Fatalf("lint after definitions = %v", lintErr)
	}

	policy, err := aclpolicy.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(policy.Groups["group:eng"]) != 1 || len(policy.IPSets["ipset:office"]) != 1 {
		t.Fatalf("definitions = groups %v, ipsets %v", policy.Groups, policy.IPSets)
	}
	if comments, commentErr := aclpolicy.LeadingComments(
		path, "groups", "group:eng",
	); commentErr != nil || len(comments) != 1 || comments[0] != "Engineering" {
		t.Errorf("group comments = %q, %v", comments, commentErr)
	}
	if !strings.Contains(readPolicy(t, path), "// Keep this comment") {
		t.Error("typed definition edit lost the policy comment")
	}

	first := readPolicy(t, path)
	if _, addErr := runTailACL(t, path, cmdGroup, subAdd,
		"--name", "group:eng", "--member", "alice@example.com"); addErr != nil {
		t.Fatal(addErr)
	}
	if got := readPolicy(t, path); got != first {
		t.Errorf("idempotent group add changed policy:\n%s\nwant:\n%s", got, first)
	}
}

func TestDefinitionRemoveSafetyAndForce(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.json")
	writeTestPolicy(t, path, `{
		"groups": {"group:eng": ["alice@example.com"], "group:unused": ["bob@example.com"]},
		"grants": [{"src": ["group:eng"], "dst": ["100.64.0.1"], "ip": ["tcp:443"]}],
	}`)

	_, err := runTailACL(t, path, cmdGroup, subRemove, "--name", "group:eng")
	if err == nil || !strings.Contains(err.Error(), "grants[0].src[0]") || !strings.Contains(err.Error(), "--force") {
		t.Fatalf("referenced removal error = %v, want site and force guidance", err)
	}
	if code := exitCode(err); code != exitFailed {
		t.Errorf("referenced removal exit code = %d, want %d", code, exitFailed)
	}
	if _, err = runTailACL(t, path, cmdGroup, subRemove, "--name", "group:unused"); err != nil {
		t.Fatal(err)
	}
	if _, err = runTailACL(t, path, cmdGroup, subRemove, "--name", "group:eng", "--force"); err != nil {
		t.Fatal(err)
	}
	policy, err := aclpolicy.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, exists := policy.Groups["group:eng"]; exists {
		t.Error("forced group removal left the definition")
	}
}

func TestDefinitionHelpAndSchemaExposeCommands(t *testing.T) {
	t.Parallel()
	for _, args := range [][]string{{cmdGroup, subAdd, "--help"}, {cmdGroup, subRemove, "--help"}, {cmdIPSet, subAdd, "--help"}, {cmdIPSet, subRemove, "--help"}} {
		var stdout strings.Builder
		err := run(
			context.Background(), args, func(string) string { return "" }, http.DefaultClient, "", &stdout, io.Discard,
		)
		if err != nil {
			t.Errorf("run(%q) = %v", args, err)
			continue
		}
		if stdout.Len() == 0 {
			t.Errorf("help for %q is empty", args)
		}
	}

	var stdout strings.Builder
	if err := run(
		context.Background(), []string{"-schema"}, func(string) string { return "" },
		http.DefaultClient, "", &stdout, io.Discard,
	); err != nil {
		t.Fatal(err)
	}
	for _, command := range []string{commandGroupAdd, commandGroupRemove, commandIPSetAdd, commandIPSetRemove} {
		if !strings.Contains(stdout.String(), `"name": "`+command+`"`) {
			t.Errorf("schema missing %q", command)
		}
	}
}
