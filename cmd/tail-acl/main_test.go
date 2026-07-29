package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/rshade/tailscale-utils/tail-acl/internal/aclpolicy"
)

func TestTypedPolicyEdits(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.json")
	writeTestPolicy(t, path, `{
		"ssh": [{
			"action": "accept",
			"src": ["autogroup:member"],
			"dst": ["tag:web"],
			"users": ["ubuntu"],
			"acceptEnv": ["LANG", "LC_*"]
		}],
		"sshTests": [{
			"src": "alice@example.com",
			"dst": ["tag:web"],
			"accept": ["ubuntu"],
			"check": ["root"],
			"deny": ["guest"],
			"srcPostureAttrs": {"node:os": "linux"}
		}]
	}`)
	getenv := func(string) string { return "" }

	commands := [][]string{
		{"--file", path, "grant", "add", "--src", "autogroup:member", "--dst", "tag:web", "--ip", "tcp:443"},
		// Adding the same grant is idempotent.
		{"--file", path, "grant", "add", "--src", "autogroup:member", "--dst", "tag:web", "--ip", "tcp:443"},
		{"--file", path, "tag-owner", "add", "tag:web", "autogroup:admin"},
		// Adding the same owner is idempotent.
		{"--file", path, "tag-owner", "add", "tag:web", "autogroup:admin"},
		{"--file", path, "host", "set", "web", "100.64.0.10"},
		{"--file", path, "posture", "set", "posture:labCompliant", "custom:labCompliant == true"},
	}
	for _, command := range commands {
		if err := run(
			context.Background(),
			command,
			getenv,
			http.DefaultClient,
			"",
			io.Discard,
			io.Discard,
		); err != nil {
			t.Fatalf("run(%q): %v", command, err)
		}
	}

	policy, err := aclpolicy.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(policy.Grants) != 1 {
		t.Fatalf("Grants = %#v", policy.Grants)
	}
	grant := policy.Grants[0]
	if grant.Source[0] != "autogroup:member" || grant.Destination[0] != "tag:web" || grant.IP[0] != "tcp:443" {
		t.Errorf("Grant = %#v", grant)
	}
	if owners := policy.TagOwners["tag:web"]; len(owners) != 1 || owners[0] != "autogroup:admin" {
		t.Errorf("TagOwners[tag:web] = %#v", owners)
	}
	if policy.Hosts["web"] != "100.64.0.10" {
		t.Errorf("Hosts[web] = %q", policy.Hosts["web"])
	}
	postures := policy.Postures["posture:labCompliant"]
	if len(postures) != 1 || postures[0] != "custom:labCompliant == true" {
		t.Errorf("Postures[posture:labCompliant] = %#v", postures)
	}
	assertSSHExtensionsPreserved(t, policy)

	if err = run(
		context.Background(),
		[]string{"--file", path, "grant", "remove", "--index", "0"},
		getenv,
		http.DefaultClient,
		"",
		io.Discard,
		io.Discard,
	); err != nil {
		t.Fatalf("grant remove: %v", err)
	}
	policy, err = aclpolicy.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(policy.Grants) != 0 {
		t.Errorf("Grants after remove = %#v", policy.Grants)
	}

	if err = run(
		context.Background(),
		[]string{"--file", path, "posture", "remove", "posture:labCompliant"},
		getenv,
		http.DefaultClient,
		"",
		io.Discard,
		io.Discard,
	); err != nil {
		t.Fatalf("posture remove: %v", err)
	}
	policy, err = aclpolicy.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(policy.Postures) != 0 {
		t.Errorf("Postures after remove = %#v", policy.Postures)
	}
	assertSSHExtensionsPreserved(t, policy)
}

func TestLocalCommandsLoadSSHExtensions(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.hujson")
	writeTestPolicy(t, path, `{
		"tagOwners": {
			"tag:ssh-only": ["autogroup:admin"]
		},
		"grants": [{
			"src": ["autogroup:member"],
			"dst": ["100.64.0.1"],
			"ip": ["tcp:443"]
		}],
		"ssh": [{
			"action": "accept",
			"src": ["autogroup:member"],
			"dst": ["autogroup:self"],
			"users": ["ubuntu"],
			"acceptEnv": ["LANG"]
		}],
		"sshTests": [{
			"src": "alice@example.com",
			"dst": ["tag:ssh-only"],
			"accept": ["ubuntu"]
		}],
		"tests": [{
			"src": "autogroup:member",
			"accept": ["100.64.0.1:443"]
		}]
	}`)

	commands := [][]string{
		{"--file", path, cmdTest},
		{"--file", path, cmdCheck, "--src", "autogroup:member", "--dst", "100.64.0.1:443"},
		{"--file", path, cmdLint},
	}
	for _, command := range commands {
		if err := run(
			context.Background(),
			command,
			func(string) string { return "" },
			nil,
			"",
			io.Discard,
			io.Discard,
		); err != nil {
			t.Errorf("run(%q): %v", command, err)
		}
	}
}

func TestGrantAddIgnoresFlagOrder(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.json")
	writeTestPolicy(t, path, `{
		"grants": [{
			"src": ["group:a", "group:b"],
			"dst": ["tag:x", "tag:y"],
			"ip": ["tcp:80", "tcp:443"]
		}]
	}`)

	err := run(
		context.Background(),
		[]string{
			"--file", path, "grant", "add",
			"--src", "group:b", "--src", "group:a",
			"--dst", "tag:y", "--dst", "tag:x",
			"--ip", "tcp:443", "--ip", "tcp:80",
		},
		func(string) string { return "" },
		http.DefaultClient,
		"",
		io.Discard,
		io.Discard,
	)
	if err != nil {
		t.Fatal(err)
	}

	policy, err := aclpolicy.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(policy.Grants) != 1 {
		t.Fatalf("Grants = %#v, want one order-insensitively deduplicated grant", policy.Grants)
	}
}

func TestTypedEditsRejectHuJSONWithoutChangingIt(t *testing.T) {
	t.Parallel()
	commands := [][]string{
		{"grant", "add", "--src", "autogroup:member", "--dst", "tag:web", "--ip", "tcp:443"},
		{"grant", "remove", "--index", "0"},
		{"tag-owner", "add", "tag:web", "autogroup:admin"},
		{"host", "set", "web", "100.64.0.10"},
		{"posture", "set", "posture:labCompliant", "custom:labCompliant == true"},
		{"posture", "remove", "posture:labCompliant"},
	}
	const original = "{\n\t// operational documentation must survive\n\t\"grants\": [],\n}\n"
	for _, command := range commands {
		t.Run(strings.Join(command[:2], " "), func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "acl.hujson")
			writeTestPolicy(t, path, original)
			args := append([]string{"--file", path}, command...)
			err := run(
				context.Background(),
				args,
				func(string) string { return "" },
				nil, // check is deliberately offline and must not need an HTTP client.
				"",
				io.Discard,
				io.Discard,
			)
			if err == nil || !strings.Contains(err.Error(), "typed edits require a .json file") {
				t.Fatalf("error = %v, want .json requirement", err)
			}
			if code := exitCode(err); code != exitUsage {
				t.Errorf("exit code = %d, want %d for a usage error", code, exitUsage)
			}
			got, readErr := os.ReadFile(path)
			if readErr != nil {
				t.Fatal(readErr)
			}
			if string(got) != original {
				t.Errorf("HuJSON changed:\n%s", got)
			}
		})
	}
}

func TestFlagErrorsDoNotPrintAPIKeyFromEnvironment(t *testing.T) {
	t.Parallel()
	const secret = "tskey-api-SECRETLEAKCANARY123"
	getenv := func(key string) string {
		if key == "TAILSCALE_API_KEY" {
			return secret
		}
		return ""
	}
	for _, args := range [][]string{{"--help"}, {"--not-a-flag"}} {
		var stderr strings.Builder
		err := run(context.Background(), args, getenv, http.DefaultClient, "", io.Discard, &stderr)
		if err == nil {
			t.Errorf("run(%q) unexpectedly succeeded", args)
		}
		if strings.Contains(stderr.String(), secret) {
			t.Errorf("run(%q) exposed API key in stderr: %s", args, stderr.String())
		}
	}
}

func TestGrantRemoveRejectsInvalidIndex(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.json")
	writeTestPolicy(t, path, `{"grants": []}`)
	err := run(
		context.Background(),
		[]string{"--file", path, "grant", "remove", "--index", "2"},
		func(string) string { return "" },
		http.DefaultClient,
		"",
		io.Discard,
		io.Discard,
	)
	if err == nil || !strings.Contains(err.Error(), "out of range") {
		t.Fatalf("error = %v, want out-of-range error", err)
	}
	if code := exitCode(err); code != exitUsage {
		t.Errorf("exit code = %d, want %d", code, exitUsage)
	}
}

func TestPostureSetAutoPrefixesBareName(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.json")
	writeTestPolicy(t, path, `{}`)

	err := run(
		context.Background(),
		[]string{"--file", path, "posture", "set", "labCompliant", "custom:labCompliant == true"},
		func(string) string { return "" },
		http.DefaultClient,
		"",
		io.Discard,
		io.Discard,
	)
	if err != nil {
		t.Fatal(err)
	}

	policy, err := aclpolicy.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	postures := policy.Postures["posture:labCompliant"]
	if len(postures) != 1 || postures[0] != "custom:labCompliant == true" {
		t.Errorf("Postures[posture:labCompliant] = %#v", postures)
	}
}

func TestPostureSetRejectsInvalidName(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		input string
	}{
		{"wrong prefix tag", "tag:web"},
		{"wrong prefix group", "group:x"},
		{"prefix alone with no name", "posture:"},
		{"empty name", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "acl.json")
			writeTestPolicy(t, path, `{}`)

			err := run(
				context.Background(),
				[]string{"--file", path, "posture", "set", tc.input, "custom:x == true"},
				func(string) string { return "" },
				http.DefaultClient,
				"",
				io.Discard,
				io.Discard,
			)
			if code := exitCode(err); code != exitUsage {
				t.Fatalf("exit code = %d, want %d (error %v)", code, exitUsage, err)
			}
			// "posture name" is common to every NormalizePostureName error message;
			// this pins the failure to name validation, not to "posture" being an
			// unrecognized top-level command.
			if err == nil || !strings.Contains(err.Error(), "posture name") {
				t.Errorf("error = %v, want a posture name validation error", err)
			}

			got, readErr := os.ReadFile(path)
			if readErr != nil {
				t.Fatal(readErr)
			}
			if string(got) != "{}" {
				t.Errorf("file changed: %s", got)
			}
		})
	}
}

func TestPostureSetRequiresAtLeastOneExpr(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.json")
	writeTestPolicy(t, path, `{}`)

	err := run(
		context.Background(),
		[]string{"--file", path, "posture", "set", "posture:labCompliant"},
		func(string) string { return "" },
		http.DefaultClient,
		"",
		io.Discard,
		io.Discard,
	)
	if code := exitCode(err); code != exitUsage {
		t.Fatalf("exit code = %d, want %d (error %v)", code, exitUsage, err)
	}
	if err == nil || !strings.Contains(err.Error(), "usage: tail-acl posture set NAME EXPR [EXPR ...]") {
		t.Errorf("error = %v, want the posture set usage string", err)
	}
}

func TestPostureSetReplacesExpressionList(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.json")
	writeTestPolicy(t, path, `{"postures": {"posture:labCompliant": ["old == true"]}}`)

	err := run(
		context.Background(),
		[]string{
			"--file", path, "posture", "set", "posture:labCompliant",
			"new == true", "also == true",
		},
		func(string) string { return "" },
		http.DefaultClient,
		"",
		io.Discard,
		io.Discard,
	)
	if err != nil {
		t.Fatal(err)
	}

	policy, err := aclpolicy.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"new == true", "also == true"}
	got := policy.Postures["posture:labCompliant"]
	if !slices.Equal(got, want) {
		t.Errorf("Postures[posture:labCompliant] = %#v, want %#v", got, want)
	}
}

func TestPostureRemoveIsIdempotent(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.json")
	writeTestPolicy(t, path, `{}`)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	for i := range 2 {
		var stdout strings.Builder
		runErr := run(
			context.Background(),
			[]string{"-format", "json", "--file", path, "posture", "remove", "posture:missing"},
			func(string) string { return "" },
			http.DefaultClient,
			"",
			&stdout,
			io.Discard,
		)
		if runErr != nil {
			t.Fatalf("run #%d: %v", i, runErr)
		}
		var res result
		if err = json.Unmarshal([]byte(stdout.String()), &res); err != nil {
			t.Fatalf("run #%d stdout is not valid JSON: %v\n%s", i, err, stdout.String())
		}
		if res.Status != statusNoChanges {
			t.Errorf("run #%d status = %q, want %q", i, res.Status, statusNoChanges)
		}
	}

	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Errorf("file changed across no-op removes:\nbefore: %s\nafter: %s", before, after)
	}
}

func TestPostureRemoveDropsKeyWhenPosturesBecomesEmpty(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.json")
	writeTestPolicy(t, path, `{"postures": {"posture:labCompliant": ["x == true"]}}`)

	err := run(
		context.Background(),
		[]string{"--file", path, "posture", "remove", "posture:labCompliant"},
		func(string) string { return "" },
		http.DefaultClient,
		"",
		io.Discard,
		io.Discard,
	)
	if err != nil {
		t.Fatal(err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(got), "postures") {
		t.Errorf("file still mentions postures after the last entry was removed: %s", got)
	}
}

func TestGrantAddPopulatesSrcPosture(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.json")
	writeTestPolicy(t, path, `{}`)

	err := run(
		context.Background(),
		[]string{
			"--file", path, "grant", "add",
			"--src", "autogroup:member", "--dst", "tag:web", "--ip", "tcp:443",
			"--src-posture", "posture:labCompliant", "--src-posture", "posture:otherReq",
		},
		func(string) string { return "" },
		http.DefaultClient,
		"",
		io.Discard,
		io.Discard,
	)
	if err != nil {
		t.Fatal(err)
	}

	policy, err := aclpolicy.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(policy.Grants) != 1 {
		t.Fatalf("Grants = %#v", policy.Grants)
	}
	got := slices.Clone(policy.Grants[0].SrcPosture)
	slices.Sort(got)
	want := []string{"posture:labCompliant", "posture:otherReq"}
	if !slices.Equal(got, want) {
		t.Errorf("Grants[0].SrcPosture = %#v, want %#v (order-insensitive)", policy.Grants[0].SrcPosture, want)
	}
}

func TestGrantAddSrcPostureParticipatesInIdentity(t *testing.T) {
	t.Parallel()

	t.Run("identical src-posture set dedupes", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(t.TempDir(), "acl.json")
		writeTestPolicy(t, path, `{}`)
		commands := [][]string{
			{
				"--file", path, "grant", "add",
				"--src", "autogroup:member", "--dst", "tag:web", "--ip", "tcp:443",
				"--src-posture", "posture:labCompliant",
			},
			{
				"--file", path, "grant", "add",
				"--src", "autogroup:member", "--dst", "tag:web", "--ip", "tcp:443",
				"--src-posture", "posture:labCompliant",
			},
		}
		for _, command := range commands {
			if err := run(
				context.Background(), command, func(string) string { return "" },
				http.DefaultClient, "", io.Discard, io.Discard,
			); err != nil {
				t.Fatalf("run(%q): %v", command, err)
			}
		}
		policy, err := aclpolicy.Load(path)
		if err != nil {
			t.Fatal(err)
		}
		if len(policy.Grants) != 1 {
			t.Errorf("Grants = %#v, want one deduplicated grant", policy.Grants)
		}
	})

	t.Run("differing src-posture is a distinct grant", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(t.TempDir(), "acl.json")
		writeTestPolicy(t, path, `{}`)
		commands := [][]string{
			{
				"--file", path, "grant", "add",
				"--src", "autogroup:member", "--dst", "tag:web", "--ip", "tcp:443",
				"--src-posture", "posture:a",
			},
			{
				"--file", path, "grant", "add",
				"--src", "autogroup:member", "--dst", "tag:web", "--ip", "tcp:443",
				"--src-posture", "posture:b",
			},
		}
		for _, command := range commands {
			if err := run(
				context.Background(), command, func(string) string { return "" },
				http.DefaultClient, "", io.Discard, io.Discard,
			); err != nil {
				t.Fatalf("run(%q): %v", command, err)
			}
		}
		policy, err := aclpolicy.Load(path)
		if err != nil {
			t.Fatal(err)
		}
		if len(policy.Grants) != 2 {
			t.Errorf("Grants = %#v, want two distinct grants", policy.Grants)
		}
	})
}

// TestGrantAddRejectsMalformedSrcPosture checks the --src-posture shape check.
// An empty-string --src-posture is deliberately not a table row here:
// stringListFlag.Set itself rejects it ("value cannot be empty") one layer
// earlier, before ValidatePostureReference ever sees it — the same exit-2
// outcome via a different code path, so it would be a near-duplicate of these
// cases rather than a meaningfully different one.
func TestGrantAddRejectsMalformedSrcPosture(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		value string
	}{
		// Bare "labCompliant" is the deliberate asymmetry case: --src-posture
		// never auto-prefixes a bare name the way "posture set" does, so it
		// must be rejected rather than silently prefixed.
		{"bare name is rejected, not auto-prefixed", "labCompliant"},
		{"wrong prefix", "tag:web"},
		{"prefix alone with no name", "posture:"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "acl.json")
			writeTestPolicy(t, path, `{}`)

			err := run(
				context.Background(),
				[]string{
					"--file", path, "grant", "add",
					"--src", "autogroup:member", "--dst", "tag:web", "--ip", "tcp:443",
					"--src-posture", tc.value,
				},
				func(string) string { return "" },
				http.DefaultClient,
				"",
				io.Discard,
				io.Discard,
			)
			if code := exitCode(err); code != exitUsage {
				t.Fatalf("exit code = %d, want %d (error %v)", code, exitUsage, err)
			}
			// "posture reference" is unique to ValidatePostureReference's error
			// message; this pins the failure to the --src-posture shape check, not
			// to --src-posture being an unrecognized flag.
			if err == nil || !strings.Contains(err.Error(), "posture reference") {
				t.Errorf("error = %v, want a posture reference validation error", err)
			}

			policy, loadErr := aclpolicy.Load(path)
			if loadErr != nil {
				t.Fatal(loadErr)
			}
			if len(policy.Grants) != 0 {
				t.Errorf("Grants = %#v, want no grant added", policy.Grants)
			}
		})
	}
}

func TestMergeUsesSharedHuJSONMerge(t *testing.T) {
	t.Parallel()
	dir1 := t.TempDir()
	dir2 := t.TempDir()
	writeTestPolicy(t, filepath.Join(dir1, "base.acl.hujson"), `{
		"grants": [{"src": ["one"], "dst": ["*"], "ip": ["*"]}],
	}`)
	writeTestPolicy(t, filepath.Join(dir2, "extra.acl.json"), `{
		"grants": [{"src": ["two"], "dst": ["*"], "ip": ["*"]}]
	}`)
	out := filepath.Join(t.TempDir(), "acl.json")

	err := run(
		context.Background(),
		[]string{"--file", out, "merge", "--dir", dir1, "--dir", dir2},
		func(string) string { return "" },
		http.DefaultClient,
		"",
		io.Discard,
		io.Discard,
	)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := aclpolicy.Load(out)
	if err != nil {
		t.Fatal(err)
	}
	if len(policy.Grants) != 2 || policy.Grants[0].Source[0] != "one" || policy.Grants[1].Source[0] != "two" {
		t.Fatalf("merged Grants = %#v", policy.Grants)
	}
}

// TestMergeRoundTripsPostureAndSrcPostureGrant authors a postures block and a
// srcPosture grant through the CLI verbs this issue adds, then confirms merge
// carries both through into the compiled policy — the workflow the issue's
// Problem Statement describes.
func TestMergeRoundTripsPostureAndSrcPostureGrant(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	fragment := filepath.Join(dir, "posture.acl.json")
	writeTestPolicy(t, fragment, `{}`)

	commands := [][]string{
		{"--file", fragment, "posture", "set", "posture:labCompliant", "custom:labCompliant == true"},
		{
			"--file", fragment, "grant", "add",
			"--src", "autogroup:member", "--dst", "tag:web", "--ip", "tcp:443",
			"--src-posture", "posture:labCompliant",
		},
	}
	for _, command := range commands {
		if err := run(
			context.Background(), command, func(string) string { return "" },
			http.DefaultClient, "", io.Discard, io.Discard,
		); err != nil {
			t.Fatalf("run(%q): %v", command, err)
		}
	}

	out := filepath.Join(t.TempDir(), "acl.json")
	err := run(
		context.Background(),
		[]string{"--file", out, "merge", "--dir", dir},
		func(string) string { return "" },
		http.DefaultClient,
		"",
		io.Discard,
		io.Discard,
	)
	if err != nil {
		t.Fatal(err)
	}

	policy, err := aclpolicy.Load(out)
	if err != nil {
		t.Fatal(err)
	}
	postures := policy.Postures["posture:labCompliant"]
	if len(postures) != 1 || postures[0] != "custom:labCompliant == true" {
		t.Errorf("merged Postures[posture:labCompliant] = %#v", postures)
	}
	if len(policy.Grants) != 1 {
		t.Fatalf("merged Grants = %#v", policy.Grants)
	}
	srcPosture := policy.Grants[0].SrcPosture
	if len(srcPosture) != 1 || srcPosture[0] != "posture:labCompliant" {
		t.Errorf("merged Grants[0].SrcPosture = %#v", srcPosture)
	}
}

// TestJSONEnvelope asserts a command's -format json output is the versioned
// result envelope on stdout, parse-clean for machine consumers.
func TestJSONEnvelope(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	writeTestPolicy(t, filepath.Join(dir, "base.acl.hujson"), `{
		"grants": [{"src": ["one"], "dst": ["*"], "ip": ["*"]}],
	}`)
	out := filepath.Join(t.TempDir(), "acl.json")

	var stdout strings.Builder
	err := run(
		context.Background(),
		[]string{"-format", "json", "--file", out, "merge", "--dir", dir},
		func(string) string { return "" },
		http.DefaultClient,
		"",
		&stdout,
		io.Discard,
	)
	if err != nil {
		t.Fatal(err)
	}
	var res result
	if err = json.Unmarshal([]byte(stdout.String()), &res); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\n%s", err, stdout.String())
	}
	if res.SchemaVersion != schemaVersion || res.Tool != "tail-acl" || res.Command != "merge" ||
		res.Status != statusOK {
		t.Errorf("envelope = %#v", res)
	}
	if res.MergedFiles == nil || *res.MergedFiles != 1 {
		t.Errorf("MergedFiles = %v, want 1", res.MergedFiles)
	}
}

func TestPolicyTestHumanOutputAndExitCodes(t *testing.T) {
	t.Parallel()
	testCases := []struct {
		name       string
		policy     string
		wantCode   int
		wantOutput []string
	}{
		{
			name: "all pass",
			policy: `{
				"grants": [{"src": ["group:dev"], "dst": ["tag:web"], "ip": ["tcp:443"]}],
				"groups": {"group:dev": ["alice@example.com"]},
				"tests": [{
					"src": "alice@example.com",
					"accept": ["tag:web:443"],
					"deny": ["tag:web:22"]
				}]
			}`,
			wantCode: exitOK,
			wantOutput: []string{
				"PASS tests[0].accept[0] alice@example.com -> tag:web:443",
				"PASS tests[0].deny[0] alice@example.com -> tag:web:22",
				"tail-acl: 2 assertions: 2 passed, 0 failed",
			},
		},
		{
			name: "assertion failure",
			policy: `{
				"grants": [{"src": ["alice@example.com"], "dst": ["tag:web"], "ip": ["tcp:443"]}],
				"tests": [{"src": "alice@example.com", "deny": ["tag:web:443"]}]
			}`,
			wantCode: exitFailed,
			wantOutput: []string{
				"FAIL tests[0].deny[0] alice@example.com -> tag:web:443",
				"tail-acl: 1 assertions: 0 passed, 1 failed",
			},
		},
		{
			name:       "missing tests",
			policy:     `{"grants": []}`,
			wantCode:   exitOK,
			wantOutput: []string{"tail-acl: no policy tests declared"},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "acl.hujson")
			writeTestPolicy(t, path, testCase.policy)
			var stdout, stderr strings.Builder
			err := run(
				context.Background(),
				[]string{"--file", path, "test"},
				func(string) string { return "" },
				http.DefaultClient,
				"",
				&stdout,
				&stderr,
			)
			if code := exitCode(err); code != testCase.wantCode {
				t.Errorf("exit code = %d, want %d (error %v)", code, testCase.wantCode, err)
			}
			for _, want := range testCase.wantOutput {
				if !strings.Contains(stdout.String(), want) {
					t.Errorf("stdout missing %q:\n%s", want, stdout.String())
				}
			}
			if stderr.Len() != 0 {
				t.Errorf("stderr = %q, want quiet", stderr.String())
			}
		})
	}
}

func TestPolicyTestJSONFailureEnvelope(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.hujson")
	writeTestPolicy(t, path, `{
		"grants": [{"src": ["alice@example.com"], "dst": ["tag:web"], "ip": ["tcp:443"]}],
		"tests": [{
			"src": "alice@example.com",
			"accept": ["tag:web:443"],
			"deny": ["tag:web:443"]
		}]
	}`)

	var stdout, stderr strings.Builder
	err := run(
		context.Background(),
		[]string{"-format", "json", "--file", path, "test"},
		func(string) string { return "" },
		http.DefaultClient,
		"",
		&stdout,
		&stderr,
	)
	if code := exitCode(err); code != exitFailed {
		t.Fatalf("exit code = %d, want %d (error %v)", code, exitFailed, err)
	}
	var res result
	if err = json.Unmarshal([]byte(stdout.String()), &res); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\n%s", err, stdout.String())
	}
	if res.SchemaVersion != schemaVersion || res.Command != cmdTest || res.Status != statusFailed {
		t.Errorf("envelope = %#v", res)
	}
	if res.Assertions == nil || len(*res.Assertions) != 2 ||
		(*res.Assertions)[0].Status != aclpolicy.AssertionPass ||
		(*res.Assertions)[1].Status != aclpolicy.AssertionFail {
		t.Errorf("Assertions = %#v", res.Assertions)
	}
	if res.TestSummary == nil || res.TestSummary.Total != 2 || res.TestSummary.Passed != 1 ||
		res.TestSummary.Failed != 1 {
		t.Errorf("TestSummary = %#v", res.TestSummary)
	}
	if stderr.Len() != 0 {
		t.Errorf("stderr = %q, want quiet", stderr.String())
	}
}

// TestPolicyTestReportsUnevaluatedSSHTests pins the signal that keeps a
// network-only run honest. sshTests load so typed edits preserve them, so a
// policy whose only assertions are sshTests must not claim no tests were
// declared, and must tell a machine consumer what went unevaluated.
func TestPolicyTestReportsUnevaluatedSSHTests(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.hujson")
	writeTestPolicy(t, path, `{
		"tagOwners": {"tag:web": ["autogroup:admin"]},
		"sshTests": [
			{"src": "alice@example.com", "dst": ["tag:web"], "accept": ["ubuntu"], "deny": ["guest"]},
			{"src": "bob@example.com", "dst": ["tag:web"], "check": ["root"]}
		]
	}`)

	var stdout, stderr strings.Builder
	err := run(
		context.Background(),
		[]string{"-format", "json", "--file", path, "test"},
		func(string) string { return "" },
		http.DefaultClient,
		"",
		&stdout,
		&stderr,
	)
	if code := exitCode(err); code != exitOK {
		t.Fatalf("exit code = %d, want %d (error %v)", code, exitOK, err)
	}
	var res result
	if err = json.Unmarshal([]byte(stdout.String()), &res); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\n%s", err, stdout.String())
	}
	if res.SSHTestsSkipped != 2 {
		t.Errorf("SSHTestsSkipped = %d, want 2", res.SSHTestsSkipped)
	}
	if !strings.Contains(res.Message, "2 sshTests preserved but not evaluated") {
		t.Errorf("Message = %q, want the unevaluated sshTests named", res.Message)
	}
	if !strings.Contains(stderr.String(), "sshTests are preserved but not evaluated") {
		t.Errorf("stderr = %q, want a warning about unevaluated sshTests", stderr.String())
	}
}

// TestPolicyTestOmitsSSHTestsSkippedWhenAbsent pins the other half of that
// contract: a policy without sshTests emits the byte-for-byte envelope it
// always did, so reporting the skip costs existing consumers nothing.
func TestPolicyTestOmitsSSHTestsSkippedWhenAbsent(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.hujson")
	writeTestPolicy(t, path, `{"tagOwners": {"tag:web": ["autogroup:admin"]}}`)

	var stdout, stderr strings.Builder
	if err := run(
		context.Background(),
		[]string{"-format", "json", "--file", path, "test"},
		func(string) string { return "" },
		http.DefaultClient,
		"",
		&stdout,
		&stderr,
	); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(stdout.String(), "ssh_tests_skipped") {
		t.Errorf("envelope carries ssh_tests_skipped with no sshTests:\n%s", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Errorf("stderr = %q, want quiet", stderr.String())
	}
}

// TestPolicyTestJSONAssertionsKeyPresence pins the machine contract: a test run
// always carries an "assertions" array — empty rather than absent when the
// policy declares no tests — while other commands omit the key entirely.
func TestPolicyTestJSONAssertionsKeyPresence(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "acl.hujson")
	writeTestPolicy(t, path, `{"grants": [{"src": ["one"], "dst": ["*"], "ip": ["*"]}]}`)

	testCases := []struct {
		name    string
		args    []string
		wantKey bool
	}{
		{"test without declared tests", []string{"--file", path, "test"}, true},
		{
			"merge does not report assertions",
			[]string{"--file", filepath.Join(dir, "out.json"), "merge", "--dir", dir},
			false,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			var stdout strings.Builder
			err := run(
				context.Background(),
				append([]string{"-format", "json"}, testCase.args...),
				func(string) string { return "" },
				http.DefaultClient,
				"",
				&stdout,
				io.Discard,
			)
			if err != nil {
				t.Fatal(err)
			}
			var envelope map[string]json.RawMessage
			if err = json.Unmarshal([]byte(stdout.String()), &envelope); err != nil {
				t.Fatalf("stdout is not valid JSON: %v\n%s", err, stdout.String())
			}
			raw, ok := envelope["assertions"]
			if ok != testCase.wantKey {
				t.Fatalf("assertions key present = %t, want %t:\n%s", ok, testCase.wantKey, stdout.String())
			}
			if testCase.wantKey && string(raw) != "[]" {
				t.Errorf("assertions = %s, want []", raw)
			}
		})
	}
}

// TestPolicyTestUnparseableRule pins the two halves of the unparseable-rule
// contract: by default the rule is warned about on stderr and named in the
// envelope while evaluation continues, and -strict refuses to report verdicts
// computed around it at all.
func TestPolicyTestUnparseableRule(t *testing.T) {
	t.Parallel()
	// acls[0] omits the port Tailscale requires, so it can never be evaluated.
	const policy = `{
		"acls": [
			{"action": "accept", "src": ["autogroup:member"], "dst": ["tag:web"]},
			{"action": "accept", "src": ["autogroup:member"], "dst": ["tag:db:5432"]}
		],
		"tests": [{"src": "alice@example.com", "accept": ["tag:db:5432"], "deny": ["tag:web:443"]}]
	}`

	t.Run("default warns and continues", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(t.TempDir(), "acl.hujson")
		writeTestPolicy(t, path, policy)
		var stdout, stderr strings.Builder
		err := run(
			context.Background(),
			[]string{"-format", "json", "--file", path, "test"},
			func(string) string { return "" },
			http.DefaultClient,
			"",
			&stdout,
			&stderr,
		)
		if code := exitCode(err); code != exitOK {
			t.Fatalf("exit code = %d, want %d (error %v)", code, exitOK, err)
		}
		if !strings.Contains(stderr.String(), "skipping unparseable policy rule") ||
			!strings.Contains(stderr.String(), "acls[0].dst[0]") {
			t.Errorf("stderr missing skip warning: %s", stderr.String())
		}
		var res result
		if err = json.Unmarshal([]byte(stdout.String()), &res); err != nil {
			t.Fatalf("stdout is not valid JSON: %v\n%s", err, stdout.String())
		}
		if len(res.Skipped) != 1 || res.Skipped[0].Rule != "acls[0].dst[0]" ||
			res.Skipped[0].Value != "tag:web" {
			t.Errorf("Skipped = %#v, want the unparseable acls[0] destination", res.Skipped)
		}
		if res.TestSummary == nil || res.TestSummary.Total != 2 {
			t.Errorf("TestSummary = %#v, want both assertions still evaluated", res.TestSummary)
		}
	})

	t.Run("strict refuses to guess", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(t.TempDir(), "acl.hujson")
		writeTestPolicy(t, path, policy)
		var stdout, stderr strings.Builder
		err := run(
			context.Background(),
			[]string{"-strict", "--file", path, "test"},
			func(string) string { return "" },
			http.DefaultClient,
			"",
			&stdout,
			&stderr,
		)
		if code := exitCode(err); code != exitUsage {
			t.Fatalf("exit code = %d, want %d (error %v)", code, exitUsage, err)
		}
		if !strings.Contains(err.Error(), "acls[0].dst[0]") {
			t.Errorf("error = %v, want it to locate the offending rule", err)
		}
		if stdout.Len() != 0 {
			t.Errorf("stdout = %q, want no verdicts in strict mode", stdout.String())
		}
	})
}

// TestPolicyTestTraceNamesParseFailure guards the decision trace against
// reporting an unparseable rule as an ordinary semantic non-match.
func TestPolicyTestTraceNamesParseFailure(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.hujson")
	writeTestPolicy(t, path, `{
		"acls": [{"action": "accept", "src": ["autogroup:member"], "dst": ["tag:web"]}],
		"tests": [{"src": "alice@example.com", "deny": ["tag:web:443"]}]
	}`)

	var stdout strings.Builder
	err := run(
		context.Background(),
		[]string{"-format", "json", "--file", path, "test"},
		func(string) string { return "" },
		http.DefaultClient,
		"",
		&stdout,
		io.Discard,
	)
	if err != nil {
		t.Fatal(err)
	}
	var res result
	if err = json.Unmarshal([]byte(stdout.String()), &res); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\n%s", err, stdout.String())
	}
	if res.Assertions == nil || len(*res.Assertions) != 1 {
		t.Fatalf("Assertions = %#v, want one", res.Assertions)
	}
	trace := strings.Join((*res.Assertions)[0].Trace, "\n")
	if !strings.Contains(trace, "acl 0: destination could not be parsed") {
		t.Errorf("trace = %q, want it to name the parse failure", trace)
	}
	if strings.Contains(trace, "acl 0: destination or port did not match") {
		t.Errorf("trace = %q, must not report a parse failure as a semantic non-match", trace)
	}
}

func TestPolicyTestCollectionFailureIsExitTwo(t *testing.T) {
	t.Parallel()
	err := run(
		context.Background(),
		[]string{"--file", filepath.Join(t.TempDir(), "missing.hujson"), "test"},
		func(string) string { return "" },
		http.DefaultClient,
		"",
		io.Discard,
		io.Discard,
	)
	if err == nil {
		t.Fatal("test unexpectedly succeeded for a missing policy")
	}
	if code := exitCode(err); code != exitUsage {
		t.Errorf("exit code = %d, want %d", code, exitUsage)
	}
}

func TestPolicyTestVerboseTraceGoesToStderr(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.hujson")
	writeTestPolicy(t, path, `{
		"grants": [{"src": ["alice@example.com"], "dst": ["tag:web"], "ip": ["tcp:443"]}],
		"tests": [{"src": "alice@example.com", "accept": ["tag:web:443"]}]
	}`)

	var stdout, stderr strings.Builder
	err := run(
		context.Background(),
		[]string{"-verbose", "--file", path, "test"},
		func(string) string { return "" },
		http.DefaultClient,
		"",
		&stdout,
		&stderr,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), "PASS tests[0].accept[0]") {
		t.Errorf("stdout = %q, want assertion result", stdout.String())
	}
	for _, want := range []string{"policy test decision", "tests[0].accept[0]", "matched"} {
		if !strings.Contains(stderr.String(), want) {
			t.Errorf("stderr missing %q: %s", want, stderr.String())
		}
	}
}

func TestCheckHumanOutputAndExitCodes(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.hujson")
	writeTestPolicy(t, path, `{
		"grants": [{"src": ["group:dev"], "dst": ["tag:web"], "ip": ["tcp:443"]}],
		"groups": {"group:dev": ["alice@example.com"]}
	}`)
	testCases := []struct {
		name       string
		args       []string
		wantCode   int
		wantOutput []string
	}{
		{
			name:     "reachable inline port",
			args:     []string{"--src", "alice@example.com", "--dst", "tag:web:443"},
			wantCode: exitOK,
			wantOutput: []string{
				"tail-acl: reachable: alice@example.com -> tag:web:443",
				"matched grant 0",
			},
		},
		{
			name:     "reachable separate port",
			args:     []string{"--src", "alice@example.com", "--dst", "tag:web", "--port", "443"},
			wantCode: exitOK,
			wantOutput: []string{
				"tail-acl: reachable: alice@example.com -> tag:web:443",
				"matched grant 0",
			},
		},
		{
			name:     "not reachable",
			args:     []string{"--src", "alice@example.com", "--dst", "tag:web:22"},
			wantCode: exitFailed,
			wantOutput: []string{
				"tail-acl: not reachable: alice@example.com -> tag:web:22",
				"no network grant or ACL matched",
			},
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			var stdout, stderr strings.Builder
			args := append([]string{"--file", path, cmdCheck}, testCase.args...)
			err := run(
				context.Background(),
				args,
				func(string) string { return "" },
				http.DefaultClient,
				"",
				&stdout,
				&stderr,
			)
			if code := exitCode(err); code != testCase.wantCode {
				t.Fatalf("exit code = %d, want %d (error %v)", code, testCase.wantCode, err)
			}
			for _, want := range testCase.wantOutput {
				if !strings.Contains(stdout.String(), want) {
					t.Errorf("stdout missing %q:\n%s", want, stdout.String())
				}
			}
			if stderr.Len() != 0 {
				t.Errorf("stderr = %q, want quiet", stderr.String())
			}
		})
	}
}

func TestCheckJSONEnvelope(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.hujson")
	writeTestPolicy(t, path, `{
		"grants": [{"src": ["tag:app"], "dst": ["tag:db"], "ip": ["5432"]}]
	}`)
	testCases := []struct {
		name      string
		port      uint16
		wantCode  int
		wantAllow bool
		wantGrant int
	}{
		{"reachable", 5432, exitOK, true, 0},
		{"not reachable", 22, exitFailed, false, -1},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			assertCheckJSON(
				t,
				path,
				testCase.port,
				testCase.wantCode,
				testCase.wantAllow,
				testCase.wantGrant,
			)
		})
	}
}

func assertCheckJSON(t *testing.T, path string, port uint16, wantCode int, wantAllow bool, wantGrant int) {
	t.Helper()
	var stdout, stderr strings.Builder
	err := run(
		context.Background(),
		[]string{
			"-format", "json", "--file", path, cmdCheck,
			"--src", "tag:app", "--dst", fmt.Sprintf("tag:db:%d", port),
		},
		func(string) string { return "" },
		nil, // check is deliberately offline and must not need an HTTP client.
		"",
		&stdout,
		&stderr,
	)
	if code := exitCode(err); code != wantCode {
		t.Fatalf("exit code = %d, want %d (error %v)", code, wantCode, err)
	}
	var res result
	if err = json.Unmarshal([]byte(stdout.String()), &res); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\n%s", err, stdout.String())
	}
	if res.SchemaVersion != schemaVersion || res.Command != cmdCheck || res.Allowed == nil ||
		*res.Allowed != wantAllow || res.Source != "tag:app" ||
		res.Destination != "tag:db" || res.Port == nil || *res.Port != port {
		t.Errorf("envelope = %#v", res)
	}
	if (res.GrantIndex == nil) != (wantGrant < 0) ||
		res.GrantIndex != nil && *res.GrantIndex != wantGrant {
		t.Errorf("GrantIndex = %v, want %d", res.GrantIndex, wantGrant)
	}
	if res.Evidence == "" || len(res.Trace) == 0 {
		t.Errorf("decision evidence missing: %#v", res)
	}
	if stderr.Len() != 0 {
		t.Errorf("stderr = %q, want quiet", stderr.String())
	}
}

// A rule the evaluator cannot decide gets its own exit code so a shell caller
// can tell "the policy denies this" from "this policy cannot answer that here".
func TestCheckIndeterminateIsExitTen(t *testing.T) {
	t.Parallel()
	policies := []struct {
		name   string
		policy string
	}{
		{"via", `{"grants": [{
			"src": ["alice@example.com"], "dst": ["tag:web"],
			"ip": ["tcp:443"], "via": ["tag:router"]
		}]}`},
		{"srcPosture", `{"grants": [{
			"src": ["alice@example.com"], "dst": ["tag:web"],
			"ip": ["tcp:443"], "srcPosture": ["posture:latestMac"]
		}]}`},
		{"unresolvable autogroup", `{"grants": [{
			"src": ["autogroup:admin"], "dst": ["tag:web"], "ip": ["tcp:443"]
		}]}`},
	}
	for _, testCase := range policies {
		name, policy := testCase.name, testCase.policy
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "acl.hujson")
			writeTestPolicy(t, path, policy)
			var stdout, stderr strings.Builder
			err := run(
				context.Background(),
				[]string{"--file", path, cmdCheck, "--src", "alice@example.com", "--dst", "tag:web:443"},
				func(string) string { return "" },
				nil,
				"",
				&stdout,
				&stderr,
			)
			if code := exitCode(err); code != exitIndeterminate {
				t.Fatalf("exit code = %d, want %d (error %v)", code, exitIndeterminate, err)
			}
			if !strings.Contains(stdout.String(), "indeterminate") {
				t.Errorf("stdout = %q, want it to report indeterminate", stdout.String())
			}
			if !strings.Contains(stdout.String(), "grant 0") {
				t.Errorf("stdout = %q, want it to name the gating grant", stdout.String())
			}
		})
	}
}

// An indeterminate answer must not serialize "allowed": false — a consumer
// reading only that key would take it for a denial.
func TestCheckIndeterminateOmitsAllowed(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.hujson")
	writeTestPolicy(t, path, `{"grants": [{
		"src": ["autogroup:admin"], "dst": ["tag:web"], "ip": ["tcp:443"]
	}]}`)
	var stdout strings.Builder
	err := run(
		context.Background(),
		[]string{
			"--file", path, "--format", formatJSON, cmdCheck,
			"--src", "alice@example.com", "--dst", "tag:web:443",
		},
		func(string) string { return "" },
		nil,
		"",
		&stdout,
		io.Discard,
	)
	if code := exitCode(err); code != exitIndeterminate {
		t.Fatalf("exit code = %d, want %d (error %v)", code, exitIndeterminate, err)
	}
	var envelope map[string]any
	if unmarshalErr := json.Unmarshal([]byte(stdout.String()), &envelope); unmarshalErr != nil {
		t.Fatalf("decoding envelope: %v\n%s", unmarshalErr, stdout.String())
	}
	if got := envelope["access"]; got != "indeterminate" {
		t.Errorf("access = %v, want indeterminate", got)
	}
	if _, present := envelope["allowed"]; present {
		t.Errorf("allowed is present (%v); an indeterminate answer must omit it", envelope["allowed"])
	}
}

func TestCheckProtocolFlagNarrowsTheQuestion(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.hujson")
	writeTestPolicy(t, path, `{"grants": [{
		"src": ["tag:app"], "dst": ["tag:db"], "ip": ["udp:5432"]
	}]}`)
	testCases := []struct {
		protocol string
		wantCode int
	}{
		{"udp", exitOK},
		{"tcp", exitFailed},
		{"any", exitOK},
	}
	for _, testCase := range testCases {
		t.Run(testCase.protocol, func(t *testing.T) {
			t.Parallel()
			err := run(
				context.Background(),
				[]string{
					"--file", path, cmdCheck, "--src", "tag:app",
					"--dst", "tag:db:5432", "--proto", testCase.protocol,
				},
				func(string) string { return "" },
				nil,
				"",
				io.Discard,
				io.Discard,
			)
			if code := exitCode(err); code != testCase.wantCode {
				t.Fatalf("exit code = %d, want %d (error %v)", code, testCase.wantCode, err)
			}
		})
	}
}

// Omitting --proto must keep asking the protocol-agnostic question the verb
// shipped with, so an existing caller's verdicts do not move.
func TestCheckDefaultsToProtocolAgnostic(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.hujson")
	writeTestPolicy(t, path, `{"grants": [{
		"src": ["tag:app"], "dst": ["tag:db"], "ip": ["udp:5432"]
	}]}`)
	err := run(
		context.Background(),
		[]string{"--file", path, cmdCheck, "--src", "tag:app", "--dst", "tag:db:5432"},
		func(string) string { return "" },
		nil,
		"",
		io.Discard,
		io.Discard,
	)
	if code := exitCode(err); code != exitOK {
		t.Fatalf("exit code = %d, want %d (error %v)", code, exitOK, err)
	}
}

func TestCheckUnknownProtocolIsExitTwo(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.hujson")
	writeTestPolicy(t, path, `{"grants": []}`)
	err := run(
		context.Background(),
		[]string{
			"--file", path, cmdCheck, "--src", "tag:app",
			"--dst", "tag:db:5432", "--proto", "sctp",
		},
		func(string) string { return "" },
		nil,
		"",
		io.Discard,
		io.Discard,
	)
	if code := exitCode(err); code != exitUsage {
		t.Fatalf("exit code = %d, want %d (error %v)", code, exitUsage, err)
	}
}

func TestCheckUsageErrorsAreExitTwo(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.hujson")
	writeTestPolicy(t, path, `{"grants": []}`)
	testCases := []struct {
		name string
		args []string
	}{
		{"missing source", []string{"--dst", "tag:web:443"}},
		{"missing inline port", []string{"--src", "alice@example.com", "--dst", "tag:web"}},
		{"inline and separate ports", []string{"--src", "alice@example.com", "--dst", "tag:web:443", "--port", "443"}},
		{
			"out of range inline and separate ports",
			[]string{"--src", "alice@example.com", "--dst", "web:65536", "--port", "443"},
		},
		{"bare IPv6 without brackets", []string{"--src", "alice@example.com", "--dst", "2001:db8::1"}},
		{"malformed unbracketed IPv6", []string{"--src", "alice@example.com", "--dst", "2001:db8::gg:443"}},
		{"port too large", []string{"--src", "alice@example.com", "--dst", "tag:web", "--port", "65536"}},
		{"negative port", []string{"--src", "alice@example.com", "--dst", "tag:web", "--port", "-1"}},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			err := run(
				context.Background(),
				append([]string{"--file", path, cmdCheck}, testCase.args...),
				func(string) string { return "" },
				nil,
				"",
				io.Discard,
				io.Discard,
			)
			if code := exitCode(err); code != exitUsage {
				t.Errorf("exit code = %d, want %d (error %v)", code, exitUsage, err)
			}
		})
	}
}

func TestCheckSeparatePortAcceptsBareIPv6Destination(t *testing.T) {
	t.Parallel()
	source, target, protocol, err := parseCheckArgs([]string{
		"--src", "alice@example.com",
		"--dst", "2001:db8::1",
		"--port", "443",
	})
	if err != nil {
		t.Fatal(err)
	}
	if source != "alice@example.com" || target != "[2001:db8::1]:443" {
		t.Errorf("source, target = %q, %q, want %q, %q",
			source, target, "alice@example.com", "[2001:db8::1]:443")
	}
	if protocol != aclpolicy.ProtocolAny {
		t.Errorf("protocol = %q, want %q", protocol, aclpolicy.ProtocolAny)
	}
}

func TestVersionFlag(t *testing.T) {
	t.Parallel()
	var stdout strings.Builder
	if err := run(
		context.Background(),
		[]string{"--version"},
		func(string) string { return "" },
		http.DefaultClient,
		"",
		&stdout,
		io.Discard,
	); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(stdout.String(), "tail-acl ") {
		t.Errorf("version = %q, want a \"tail-acl \" prefix", stdout.String())
	}
}

func TestHelpDocumentsCheckAndExitCodes(t *testing.T) {
	t.Parallel()
	var stderr strings.Builder
	err := run(
		context.Background(),
		[]string{"--help"},
		func(string) string { return "" },
		http.DefaultClient,
		"",
		io.Discard,
		&stderr,
	)
	if !errors.Is(err, flag.ErrHelp) {
		t.Fatalf("error = %v, want flag.ErrHelp", err)
	}
	for _, want := range []string{
		"check          Answer one reachability question locally",
		"posture set    Add or replace a posture's expression list",
		"check --src alice@example.com --dst tag:web:443",
		"Statically lint policy hygiene (dead grants, undefined refs, over-broad *)",
		"# static policy hygiene findings",
		"0  success; check reports reachable",
		"1  operation or policy assertion failed; check reports not reachable",
		"2  usage, input, or collection error",
		"10 indeterminate",
		"Also returned by",
	} {
		if !strings.Contains(stderr.String(), want) {
			t.Errorf("help missing %q:\n%s", want, stderr.String())
		}
	}
}

func TestSchemaFlagIsMachineReadable(t *testing.T) {
	t.Parallel()
	var stdout strings.Builder
	if err := run(
		context.Background(),
		[]string{"-schema"},
		func(string) string { return "" },
		http.DefaultClient,
		"",
		&stdout,
		io.Discard,
	); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Name         string                `json:"name"`
		Commands     []schemaCommand       `json:"commands"`
		LintFindings []aclpolicy.LintCheck `json:"lint_findings"`
		ExitCodes    map[string]string     `json:"exit_codes"`
	}
	if err := json.Unmarshal([]byte(stdout.String()), &doc); err != nil {
		t.Fatalf("schema is not valid JSON: %v\n%s", err, stdout.String())
	}
	if doc.Name != "tail-acl" || len(doc.Commands) == 0 || doc.ExitCodes["2"] == "" {
		t.Errorf("schema = %#v", doc)
	}
	if !slices.ContainsFunc(doc.LintFindings, func(check aclpolicy.LintCheck) bool {
		return check.ID == aclpolicy.LintUndefinedReference
	}) {
		t.Errorf("schema lint_findings = %#v, want the finding catalog", doc.LintFindings)
	}
	if !slices.ContainsFunc(doc.Commands, func(command schemaCommand) bool { return command.Name == cmdTest }) {
		t.Errorf("schema commands = %#v, want %q", doc.Commands, cmdTest)
	}
	if !slices.ContainsFunc(doc.Commands, func(command schemaCommand) bool { return command.Name == cmdCheck }) {
		t.Errorf("schema commands = %#v, want %q", doc.Commands, cmdCheck)
	}
	if !slices.ContainsFunc(doc.Commands, func(command schemaCommand) bool { return command.Name == cmdLint }) {
		t.Errorf("schema commands = %#v, want %q", doc.Commands, cmdLint)
	}
	if !slices.ContainsFunc(doc.Commands, func(command schemaCommand) bool { return command.Name == "posture set" }) {
		t.Errorf("schema commands = %#v, want %q", doc.Commands, "posture set")
	}
	if !slices.ContainsFunc(
		doc.Commands,
		func(command schemaCommand) bool { return command.Name == "posture remove" },
	) {
		t.Errorf("schema commands = %#v, want %q", doc.Commands, "posture remove")
	}
}

func TestExitCodeMapping(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		err  error
		want int
	}{
		{"nil", nil, exitOK},
		{"help", flag.ErrHelp, exitOK},
		{"usage", usageError{errors.New("bad flag")}, exitUsage},
		{"wrapped usage", fmt.Errorf("context: %w", usageError{errors.New("x")}), exitUsage},
		{"operation", errors.New("api failed"), exitFailed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := exitCode(tc.err); got != tc.want {
				t.Errorf("exitCode(%v) = %d, want %d", tc.err, got, tc.want)
			}
		})
	}
}

func TestValidateAndUploadUseTailscaleClient(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.json")
	writeTestPolicy(t, path, `{"grants": []}`)

	var requests []string
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.Method+" "+r.URL.Path)
		username, password, ok := r.BasicAuth()
		if !ok || username != "token" || password != "" {
			t.Errorf("BasicAuth = (%q, %q, %v)", username, password, ok)
		}
		if r.Header.Get("Content-Type") != "application/hujson" {
			t.Errorf("Content-Type = %q", r.Header.Get("Content-Type"))
		}
		_, _ = io.Copy(io.Discard, r.Body)
	}))
	defer server.Close()

	getenv := func(key string) string {
		return map[string]string{
			"TAILSCALE_API_KEY": "token",
			"TAILSCALE_TAILNET": "example.com",
		}[key]
	}
	for _, command := range [][]string{
		{"--file", path, "validate"},
		{"--file", path, "--if-match", `"etag"`, "upload"},
	} {
		if err := run(
			context.Background(),
			command,
			getenv,
			server.Client(),
			server.URL,
			io.Discard,
			io.Discard,
		); err != nil {
			t.Fatalf("run(%q): %v", command, err)
		}
	}

	want := []string{
		"POST /api/v2/tailnet/example.com/acl/validate",
		"POST /api/v2/tailnet/example.com/acl",
	}
	if len(requests) != len(want) {
		t.Fatalf("requests = %v, want %v", requests, want)
	}
	for i := range want {
		if requests[i] != want[i] {
			t.Errorf("requests[%d] = %q, want %q", i, requests[i], want[i])
		}
	}
}

func TestPlanPrintsLiveDiffWithoutUploading(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.hujson")
	writeTestPolicy(t, path, `{
		"grants": [{"src": ["*"], "dst": ["tag:web"], "ip": ["tcp:443"]}],
	}`)

	var requests []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.Method+" "+r.URL.Path)
		switch r.URL.Path {
		case "/api/v2/tailnet/example.com/acl":
			if r.Method != http.MethodGet {
				t.Errorf("policy method = %s, want GET", r.Method)
			}
			w.Header().Set("ETag", `"etag-plan"`)
			_, _ = io.WriteString(w, `{"grants": []}`)
		case "/api/v2/tailnet/example.com/acl/validate":
			if r.Method != http.MethodPost {
				t.Errorf("validate method = %s, want POST", r.Method)
			}
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()

	getenv := func(key string) string {
		return map[string]string{
			"TAILSCALE_API_KEY": "token",
			"TAILSCALE_TAILNET": "example.com",
		}[key]
	}
	var output strings.Builder
	if err := run(
		context.Background(),
		[]string{"--file", path, "plan"},
		getenv,
		server.Client(),
		server.URL,
		&output,
		io.Discard,
	); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"--- deployed",
		"+++ " + path,
		"plan valid; changes found for tailnet example.com",
		`ETag "etag-plan"`,
	} {
		if !strings.Contains(output.String(), want) {
			t.Errorf("plan output missing %q:\n%s", want, output.String())
		}
	}
	wantRequests := []string{
		"GET /api/v2/tailnet/example.com/acl",
		"POST /api/v2/tailnet/example.com/acl/validate",
	}
	if strings.Join(requests, "\n") != strings.Join(wantRequests, "\n") {
		t.Errorf("requests = %v, want %v", requests, wantRequests)
	}
}

func TestValidateRequiresCredentials(t *testing.T) {
	t.Parallel()
	err := run(
		context.Background(),
		[]string{"validate"},
		func(string) string { return "" },
		http.DefaultClient,
		"",
		io.Discard,
		io.Discard,
	)
	if err == nil || !strings.Contains(err.Error(), "TAILSCALE_TAILNET") {
		t.Fatalf("error = %v, want missing tailnet error", err)
	}
	if code := exitCode(err); code != exitUsage {
		t.Errorf("exit code = %d, want %d", code, exitUsage)
	}
}

func TestLintHumanOutputAndExitCodes(t *testing.T) {
	t.Parallel()
	testCases := []struct {
		name       string
		policy     string
		wantCode   int
		wantOutput []string
	}{
		{
			name: "clean policy",
			policy: `{
				"groups": {"group:dev": ["alice@example.com"]},
				"tagOwners": {"tag:web": ["group:dev"]},
				"grants": [{"src": ["group:dev"], "dst": ["tag:web:443"], "ip": ["tcp:443"]}]
			}`,
			wantCode:   exitOK,
			wantOutput: []string{"tail-acl: no policy hygiene findings"},
		},
		{
			name:     "errors present",
			policy:   `{"grants": [{"src": ["group:missing"], "dst": ["tag:web:443"], "ip": ["tcp:443"]}]}`,
			wantCode: exitFailed,
			wantOutput: []string{
				"ERROR dst-tag-no-owner grants[0].dst[0] tag:web",
				"ERROR undefined-reference grants[0].src[0] group:missing",
				"tail-acl: 2 findings: 2 error, 0 warn, 0 info",
			},
		},
		{
			name: "invalid SSH-only selectors",
			policy: `{
				"ssh": [{"action": "accept", "src": ["group:ghost"], "dst": ["*"], "users": ["ubuntu"]}],
				"sshTests": [{"src": "alice@example.com", "dst": ["tag:missing"], "accept": ["ubuntu"]}]
			}`,
			wantCode: exitFailed,
			wantOutput: []string{
				"ERROR undefined-reference ssh[0].src[0] group:ghost",
				"ERROR dst-tag-no-owner sshTests[0].dst[0] tag:missing",
				"tail-acl: 2 findings: 2 error, 0 warn, 0 info",
			},
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "acl.hujson")
			writeTestPolicy(t, path, testCase.policy)
			var stdout, stderr strings.Builder
			err := run(
				context.Background(),
				[]string{"--file", path, cmdLint},
				func(string) string { return "" },
				nil, // lint is offline and must not need an HTTP client.
				"",
				&stdout,
				&stderr,
			)
			if code := exitCode(err); code != testCase.wantCode {
				t.Fatalf("exit code = %d, want %d (error %v)", code, testCase.wantCode, err)
			}
			for _, want := range testCase.wantOutput {
				if !strings.Contains(stdout.String(), want) {
					t.Errorf("stdout missing %q:\n%s", want, stdout.String())
				}
			}
			if stderr.Len() != 0 {
				t.Errorf("stderr = %q, want quiet", stderr.String())
			}
		})
	}
}

func TestLintJSONEnvelope(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.hujson")
	writeTestPolicy(t, path, `{"grants": [{"src": ["group:missing"], "dst": ["tag:web:443"], "ip": ["tcp:443"]}]}`)

	var stdout, stderr strings.Builder
	err := run(
		context.Background(),
		[]string{"-format", "json", "--file", path, cmdLint},
		func(string) string { return "" },
		nil,
		"",
		&stdout,
		&stderr,
	)
	if code := exitCode(err); code != exitFailed {
		t.Fatalf("exit code = %d, want %d (error %v)", code, exitFailed, err)
	}
	var res result
	if err = json.Unmarshal([]byte(stdout.String()), &res); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\n%s", err, stdout.String())
	}
	if res.SchemaVersion != schemaVersion || res.Command != cmdLint || res.Status != statusFailed {
		t.Errorf("envelope = %#v", res)
	}
	if res.Findings == nil || len(*res.Findings) != 2 {
		t.Fatalf("Findings = %#v, want two", res.Findings)
	}
	if res.LintSummary == nil || res.LintSummary.Error != 2 || res.LintSummary.Total != 2 {
		t.Errorf("LintSummary = %#v", res.LintSummary)
	}
	for _, finding := range *res.Findings {
		if finding.ID == "" || finding.Severity == "" || finding.Rule == "" || len(finding.Trace) == 0 {
			t.Errorf("finding missing required fields: %#v", finding)
		}
	}
	if stderr.Len() != 0 {
		t.Errorf("stderr = %q, want quiet", stderr.String())
	}
}

func TestLintVerboseTraceGoesToStderr(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.hujson")
	writeTestPolicy(t, path, `{"grants": [{"src": ["group:missing"], "dst": ["tag:web:443"], "ip": ["tcp:443"]}]}`)

	var stdout, stderr strings.Builder
	err := run(
		context.Background(),
		[]string{"-verbose", "--file", path, cmdLint},
		func(string) string { return "" },
		nil,
		"",
		&stdout,
		&stderr,
	)
	if code := exitCode(err); code != exitFailed {
		t.Fatalf("exit code = %d, want %d (error %v)", code, exitFailed, err)
	}
	if !strings.Contains(stdout.String(), "undefined-reference") {
		t.Errorf("stdout = %q, want the finding", stdout.String())
	}
	for _, want := range []string{"lint decision", "undefined-reference"} {
		if !strings.Contains(stderr.String(), want) {
			t.Errorf("stderr missing %q: %s", want, stderr.String())
		}
	}
}

// TestLintFlags pins the two configurable behaviors: the -severity exit
// threshold and the -wildcard policy.
func TestLintFlags(t *testing.T) {
	t.Parallel()
	testCases := []struct {
		name     string
		policy   string
		args     []string
		wantCode int
	}{
		{
			name:     "info under default warn threshold exits zero",
			policy:   `{"groups": {"group:dev": ["alice@example.com"]}, "tagOwners": {"tag:orphan": ["group:dev"]}}`,
			args:     nil,
			wantCode: exitOK,
		},
		{
			name:     "severity info promotes info to a failure",
			policy:   `{"groups": {"group:dev": ["alice@example.com"]}, "tagOwners": {"tag:orphan": ["group:dev"]}}`,
			args:     []string{"-severity", "info"},
			wantCode: exitFailed,
		},
		{
			name:     "any-to-any wildcard warns by default",
			policy:   `{"grants": [{"src": ["*"], "dst": ["*:443"], "ip": ["tcp:443"]}]}`,
			args:     nil,
			wantCode: exitFailed,
		},
		{
			name:     "wildcard off suppresses the wildcard finding",
			policy:   `{"grants": [{"src": ["*"], "dst": ["*:443"], "ip": ["tcp:443"]}]}`,
			args:     []string{"-wildcard", "off"},
			wantCode: exitOK,
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "acl.hujson")
			writeTestPolicy(t, path, testCase.policy)
			err := run(
				context.Background(),
				append([]string{"--file", path, cmdLint}, testCase.args...),
				func(string) string { return "" },
				nil,
				"",
				io.Discard,
				io.Discard,
			)
			if code := exitCode(err); code != testCase.wantCode {
				t.Errorf("exit code = %d, want %d (error %v)", code, testCase.wantCode, err)
			}
		})
	}
}

func TestLintCollectionFailureIsExitTwo(t *testing.T) {
	t.Parallel()
	err := run(
		context.Background(),
		[]string{"--file", filepath.Join(t.TempDir(), "missing.hujson"), cmdLint},
		func(string) string { return "" },
		nil,
		"",
		io.Discard,
		io.Discard,
	)
	if code := exitCode(err); code != exitUsage {
		t.Errorf("exit code = %d, want %d (error %v)", code, exitUsage, err)
	}
}

func TestLintUsageErrorsAreExitTwo(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.hujson")
	writeTestPolicy(t, path, `{"grants": []}`)
	for _, args := range [][]string{
		{"-severity", "bogus"},
		{"-wildcard", "bogus"},
		{"unexpected-arg"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			t.Parallel()
			err := run(
				context.Background(),
				append([]string{"--file", path, cmdLint}, args...),
				func(string) string { return "" },
				nil,
				"",
				io.Discard,
				io.Discard,
			)
			if code := exitCode(err); code != exitUsage {
				t.Errorf("exit code = %d, want %d (error %v)", code, exitUsage, err)
			}
		})
	}
}

func writeTestPolicy(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func assertSSHExtensionsPreserved(t *testing.T, policy *aclpolicy.Policy) {
	t.Helper()
	if len(policy.SSH) != 1 || !slices.Equal(policy.SSH[0].AcceptEnv, []string{"LANG", "LC_*"}) {
		t.Errorf("SSH extensions were not preserved across typed edits: %#v", policy.SSH)
	}
	if len(policy.SSHTests) != 1 {
		t.Fatalf("SSHTests were not preserved across typed edits: %#v", policy.SSHTests)
	}
	test := policy.SSHTests[0]
	if test.Source != "alice@example.com" ||
		!slices.Equal(test.Destination, []string{"tag:web"}) ||
		!slices.Equal(test.Accept, []string{"ubuntu"}) ||
		!slices.Equal(test.Check, []string{"root"}) ||
		!slices.Equal(test.Deny, []string{"guest"}) ||
		test.SrcPostureAttrs["node:os"] != "linux" {
		t.Errorf("SSHTests were not preserved across typed edits: %#v", policy.SSHTests)
	}
}
