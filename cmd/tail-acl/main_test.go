package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
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
	"time"

	"github.com/tailscale/hujson"
	tailscale "tailscale.com/client/tailscale/v2"

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

type huJSONEditTestCase struct {
	name    string
	command []string
	want    string
	absent  string
}

func TestTypedEditsPreserveHuJSON(t *testing.T) {
	t.Parallel()
	testCases := []huJSONEditTestCase{
		{
			commandGrantAdd,
			[]string{"grant", "add", "--src", "tag:app", "--dst", "tag:db", "--ip", "tcp:5432"},
			`"tag:app"`,
			"",
		},
		{commandGrantRemove, []string{"grant", "remove", "--index", "0"}, `"group:keep"`, `"group:old"`},
		{
			// The owner must be absent from the fixture, or Contains passes on
			// the unedited input and the subtest asserts nothing. Matching the
			// whole list also proves the owner landed on tag:web, not tag:db.
			commandTagOwnerAdd + " existing tag",
			[]string{"tag-owner", "add", "tag:web", "autogroup:owner"},
			`"tag:web": ["group:ops", "autogroup:owner"]`,
			"",
		},
		{
			commandTagOwnerAdd + " new tag",
			[]string{"tag-owner", "add", "tag:brandnew", "autogroup:owner"},
			`"tag:brandnew"`,
			"",
		},
		{commandHostSet, []string{"host", "set", "web", "100.64.0.10"}, `"100.64.0.10"`, ""},
		{
			commandPostureSet,
			[]string{"posture", "set", "posture:labCompliant", "custom:labCompliant == true"},
			`"custom:labCompliant == true"`,
			`"old == true"`,
		},
		{
			commandPostureRemove,
			[]string{"posture", "remove", "posture:labCompliant"},
			`"posture:keep"`,
			`"posture:labCompliant"`,
		},
	}
	const original = `{
	// Owner: platform-team. Do not hand-edit without review.
	"tagOwners": {
		"tag:web": ["group:ops"], // web front ends
		"tag:db":  ["autogroup:admin"],
	},
	"hosts": {
		"legacy": "100.64.0.9", // old alias
	},
	"postures": {
		"posture:labCompliant": ["old == true"], // lab devices
		"posture:keep": ["keep == true"],
	},
	"grants": [
		// Existing grant may be removed.
		{"src": ["group:old"], "dst": ["tag:web"], "ip": ["tcp:443"]},
		{"src": ["group:keep"], "dst": ["tag:db"], "ip": ["tcp:5432"]},
	],
	"groups": {
		"group:long": ["z@example.com"],
		"group:a":    ["a@example.com"], // this block is never edited
	},
	"tests": [
		// Network assertions must survive.
		{"src": "alice@example.com", "deny": ["tag:db:5432"]},
	],
}
`
	for _, testCase := range testCases {
		for _, extension := range []string{".json", ".hujson"} {
			t.Run(testCase.name+extension, func(t *testing.T) {
				t.Parallel()
				assertTypedEditPreservation(t, testCase, extension, original)
			})
		}
	}
}

func assertTypedEditPreservation(t *testing.T, testCase huJSONEditTestCase, extension, original string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "acl"+extension)
	writeTestPolicy(t, path, original)
	args := append([]string{"--file", path}, testCase.command...)
	if err := run(
		context.Background(),
		args,
		func(string) string { return "" },
		nil,
		"",
		io.Discard,
		io.Discard,
	); err != nil {
		t.Fatalf("run(%q): %v", testCase.command, err)
	}
	got, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatal(readErr)
	}
	output := string(got)
	for _, preserved := range []string{
		"// Owner: platform-team. Do not hand-edit without review.",
		"// web front ends",
		"// old alias",
		"// Network assertions must survive.",
		`{"src": "alice@example.com", "deny": ["tag:db:5432"]},`,
	} {
		if !strings.Contains(output, preserved) {
			t.Errorf("%s output lost %q:\n%s", testCase.name, preserved, output)
		}
	}
	// No command touches "groups" or "tests", so the whole tail from "groups"
	// onward must come through untouched. Comparing against hujson's own
	// formatting of the input — rather than the input verbatim — keeps this
	// assertion about the patch. hujson re-derives column alignment for the
	// entire document, so an assertion pinned to the input's spacing would be
	// measuring the formatter instead of the edit.
	tail := untouchedTail(t, formatLikeHuJSON(t, original))
	if !strings.Contains(output, tail) {
		t.Errorf("%s disturbed a region it never edited:\nwant tail:\n%s\ngot:\n%s",
			testCase.name, tail, output)
	}
	if !strings.Contains(output, testCase.want) {
		t.Errorf("%s output missing edit %q:\n%s", testCase.name, testCase.want, output)
	}
	if testCase.absent != "" && strings.Contains(output, testCase.absent) {
		t.Errorf("%s output still contains %q:\n%s", testCase.name, testCase.absent, output)
	}
	if testCase.name == commandPostureSet && !strings.Contains(output, "// lab devices") {
		t.Errorf("%s output lost the modified entry's comment:\n%s", testCase.name, output)
	}
	assertPolicyKeyOrder(t, output, "tagOwners", "hosts", "postures", "grants", "groups", "tests")
}

func assertPolicyKeyOrder(t *testing.T, policy string, keys ...string) {
	t.Helper()
	previous := -1
	for _, key := range keys {
		index := strings.Index(policy, `"`+key+`"`)
		if index < 0 {
			t.Errorf("policy is missing top-level key %q:\n%s", key, policy)
			continue
		}
		if index <= previous {
			t.Errorf("top-level key %q is out of order:\n%s", key, policy)
		}
		previous = index
	}
}

// formatLikeHuJSON renders policy the way a typed edit will, so a test can
// assert on the untouched parts of the document without also asserting how
// hujson chose to lay them out.
func formatLikeHuJSON(t *testing.T, policy string) string {
	t.Helper()
	value, err := hujson.Parse([]byte(policy))
	if err != nil {
		t.Fatal(err)
	}
	value.Format()
	return string(value.Pack())
}

// untouchedTail returns the part of a formatted policy that no typed edit
// command touches: everything from the "groups" block onward.
func untouchedTail(t *testing.T, formatted string) string {
	t.Helper()
	const marker = "\t\"groups\": {"
	start := strings.Index(formatted, marker)
	if start < 0 {
		t.Fatalf("formatted policy has no %q block:\n%s", marker, formatted)
	}
	return formatted[start:]
}

// collapseSpaces squeezes runs of spaces so an assertion about policy content
// does not also pin hujson's derived column alignment.
func collapseSpaces(s string) string {
	for strings.Contains(s, "  ") {
		s = strings.ReplaceAll(s, "  ", " ")
	}
	return s
}

// Load matches struct fields case-insensitively, so a policy in Tailscale's
// legacy capitalized style validates and populates the typed Policy. The patch
// pointer must therefore be built from the name the file actually uses, or the
// edit targets a member that is not there.
func TestTypedEditsRespectLegacyCapitalizedKeys(t *testing.T) {
	t.Parallel()
	testCases := []struct {
		name    string
		command []string
		want    string
	}{
		{
			commandTagOwnerAdd,
			[]string{"tag-owner", "add", "tag:web", "autogroup:owner"},
			`"tag:web": ["group:ops", "autogroup:owner"]`,
		},
		{commandHostSet, []string{"host", "set", "db", "100.64.0.2"}, `"db": "100.64.0.2"`},
		{
			commandGrantAdd,
			[]string{"grant", "add", "--src", "tag:app", "--dst", "tag:db", "--ip", "tcp:5432"},
			`"tag:app"`,
		},
		{commandGrantRemove, []string{"grant", "remove", "--index", "0"}, `"Grants": []`},
	}
	const original = `{
	// Authored in the legacy capitalized style.
	"TagOwners": {"tag:web": ["group:ops"]},
	"Hosts": {"legacy": "100.64.0.9"},
	"Grants": [{"src": ["group:old"], "dst": ["tag:web"], "ip": ["tcp:443"]}],
}
`
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			assertLegacyKeysSurvive(t, testCase.name, testCase.command, testCase.want, original)
		})
	}
}

func assertLegacyKeysSurvive(t *testing.T, name string, command []string, want, original string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "acl.hujson")
	writeTestPolicy(t, path, original)
	if err := run(
		context.Background(),
		append([]string{"--file", path}, command...),
		func(string) string { return "" },
		nil,
		"",
		io.Discard,
		io.Discard,
	); err != nil {
		t.Fatalf("run(%q): %v", command, err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	output := string(got)
	// hujson re-derives column alignment, so match on a whitespace-collapsed
	// copy rather than pinning its spacing.
	if !strings.Contains(collapseSpaces(output), want) {
		t.Errorf("%s did not apply: want %q in:\n%s", name, want, output)
	}
	// The operator's spelling must survive, and the edit must not introduce a
	// second, lowercase copy of the same key.
	for _, key := range []string{"TagOwners", "Hosts", "Grants"} {
		if !strings.Contains(output, `"`+key+`"`) {
			t.Errorf("%s renamed %q:\n%s", name, key, output)
		}
		if lowered := strings.ToLower(key[:1]) + key[1:]; strings.Contains(output, `"`+lowered+`"`) {
			t.Errorf("%s added a duplicate %q key:\n%s", name, lowered, output)
		}
	}
}

func TestGrantAddPreservesCommentInEmptyArray(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.hujson")
	writeTestPolicy(t, path, `{
		"grants": [
			// Grants approved in review belong here.
		],
	}`)
	err := run(
		context.Background(),
		[]string{
			"--file", path, "grant", "add",
			"--src", "autogroup:member", "--dst", "tag:web", "--ip", "tcp:443",
		},
		func(string) string { return "" },
		nil,
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
	if !strings.Contains(string(got), "// Grants approved in review belong here.") {
		t.Errorf("grant add lost the empty array's comment:\n%s", got)
	}
}

type canonicalEditTestCase struct {
	name    string
	command []string
	mutate  func(*aclpolicy.Policy)
}

func TestTypedEditsMatchCanonicalJSONOutput(t *testing.T) {
	t.Parallel()
	testCases := []canonicalEditTestCase{
		{
			commandGrantAdd,
			[]string{"grant", "add", "--src", "group:new", "--dst", "tag:db", "--ip", "tcp:5432"},
			func(policy *aclpolicy.Policy) {
				policy.Grants = append(policy.Grants, tailscale.Grant{
					Source:      []string{"group:new"},
					Destination: []string{"tag:db"},
					IP:          []string{"tcp:5432"},
				})
			},
		},
		{
			commandGrantRemove,
			[]string{"grant", "remove", "--index", "0"},
			func(policy *aclpolicy.Policy) {
				policy.Grants = slices.Delete(policy.Grants, 0, 1)
			},
		},
		{
			commandTagOwnerAdd,
			[]string{"tag-owner", "add", "tag:web", "autogroup:admin"},
			func(policy *aclpolicy.Policy) {
				policy.TagOwners["tag:web"] = append(policy.TagOwners["tag:web"], "autogroup:admin")
			},
		},
		{
			commandHostSet,
			[]string{"host", "set", "web", "100.64.0.10"},
			func(policy *aclpolicy.Policy) {
				policy.Hosts["web"] = "100.64.0.10"
			},
		},
		{
			commandPostureSet,
			[]string{"posture", "set", "posture:labCompliant", "custom:labCompliant == true"},
			func(policy *aclpolicy.Policy) {
				policy.Postures["posture:labCompliant"] = []string{"custom:labCompliant == true"}
			},
		},
		{
			commandPostureRemove,
			[]string{"posture", "remove", "posture:labCompliant"},
			func(policy *aclpolicy.Policy) {
				delete(policy.Postures, "posture:labCompliant")
			},
		},
	}
	const input = `{
		"tagOwners": {"tag:web": ["group:ops"], "tag:db": ["autogroup:admin"]},
		"hosts": {"web": "100.64.0.9"},
		"postures": {
			"posture:labCompliant": ["old == true"],
			"posture:keep": ["keep == true"]
		},
		"grants": [
			{"src": ["group:old"], "dst": ["tag:web"], "ip": ["tcp:443"]},
			{"src": ["group:keep"], "dst": ["tag:db"], "ip": ["tcp:5432"]}
		]
	}`
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			assertCanonicalEditOutput(t, testCase, input)
		})
	}
}

func assertCanonicalEditOutput(t *testing.T, testCase canonicalEditTestCase, input string) {
	t.Helper()
	dir := t.TempDir()
	sourcePath := filepath.Join(dir, "source.json")
	actualPath := filepath.Join(dir, "actual.json")
	expectedPath := filepath.Join(dir, "expected.json")
	writeTestPolicy(t, sourcePath, input)
	policy, err := aclpolicy.Load(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	if err = aclpolicy.Write(actualPath, policy); err != nil {
		t.Fatal(err)
	}
	if err = aclpolicy.Write(expectedPath, policy); err != nil {
		t.Fatal(err)
	}
	expectedPolicy, err := aclpolicy.Load(expectedPath)
	if err != nil {
		t.Fatal(err)
	}
	testCase.mutate(expectedPolicy)
	if err = aclpolicy.Write(expectedPath, expectedPolicy); err != nil {
		t.Fatal(err)
	}

	args := append([]string{"--file", actualPath}, testCase.command...)
	if err = run(
		context.Background(),
		args,
		func(string) string { return "" },
		nil,
		"",
		io.Discard,
		io.Discard,
	); err != nil {
		t.Fatalf("run(%q): %v", testCase.command, err)
	}
	actual, err := os.ReadFile(actualPath)
	if err != nil {
		t.Fatal(err)
	}
	expected, err := os.ReadFile(expectedPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(actual, expected) {
		t.Errorf(
			"canonical JSON changed from the previous writer:\nactual:\n%s\nexpected:\n%s",
			actual,
			expected,
		)
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

// Removing the last member must empty the container, not delete the key.
// Deleting the key carries its comments out with it, which is exactly the data
// loss comment-preserving edits exist to prevent.
func TestRemovingLastEntryKeepsTheCommentedBlock(t *testing.T) {
	t.Parallel()
	testCases := []struct {
		name    string
		command []string
		policy  string
		want    string
	}{
		{
			commandPostureRemove,
			[]string{"posture", "remove", "posture:labCompliant"},
			"{\n\t// Postures: approved by compliance, do not delete this block.\n" +
				"\t\"postures\": {\"posture:labCompliant\": [\"x == true\"]},\n}\n",
			`"postures": {}`,
		},
		{
			commandGrantRemove,
			[]string{"grant", "remove", "--index", "0"},
			"{\n\t// SECURITY: this grants block is reviewed quarterly. Ticket SEC-1234.\n" +
				"\t\"grants\": [{\"src\": [\"group:a\"], \"dst\": [\"tag:b\"], \"ip\": [\"tcp:1\"]}],\n}\n",
			`"grants": []`,
		},
	}
	for _, testCase := range testCases {
		for _, extension := range []string{".json", ".hujson"} {
			t.Run(testCase.name+extension, func(t *testing.T) {
				t.Parallel()
				assertEmptiedBlockKeepsComment(t, testCase.command, testCase.policy, testCase.want, extension)
			})
		}
	}
}

func assertEmptiedBlockKeepsComment(t *testing.T, command []string, policy, want, extension string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "acl"+extension)
	writeTestPolicy(t, path, policy)
	if err := run(
		context.Background(),
		append([]string{"--file", path}, command...),
		func(string) string { return "" },
		http.DefaultClient,
		"",
		io.Discard,
		io.Discard,
	); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	output := string(got)
	comment := strings.SplitN(strings.SplitN(policy, "\n\t", 2)[1], "\n", 2)[0]
	if !strings.Contains(output, comment) {
		t.Errorf("removing the last entry lost %q:\n%s", comment, output)
	}
	if !strings.Contains(output, want) {
		t.Errorf("output missing %q:\n%s", want, output)
	}
	if _, err = aclpolicy.Load(path); err != nil {
		t.Errorf("emptied policy no longer loads: %v\n%s", err, output)
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
		assertPolicyTestUnparseableDefault(t, policy)
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

func assertPolicyTestUnparseableDefault(t *testing.T, policy string) {
	t.Helper()
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
	if code := exitCode(err); code != exitIndeterminate {
		t.Fatalf("exit code = %d, want %d (error %v)", code, exitIndeterminate, err)
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
	if res.TestSummary.Indeterminate != 1 || res.Status != statusIndeterminate {
		t.Errorf("result = %#v, want one indeterminate assertion", res)
	}
	if res.Assertions == nil || (*res.Assertions)[1].Status != aclpolicy.AssertionIndeterminate {
		t.Errorf("Assertions = %#v, want the deny to be indeterminate", res.Assertions)
	}
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
	if code := exitCode(err); code != exitIndeterminate {
		t.Fatalf("exit code = %d, want %d (error %v)", code, exitIndeterminate, err)
	}
	var res result
	if err = json.Unmarshal([]byte(stdout.String()), &res); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\n%s", err, stdout.String())
	}
	if res.Assertions == nil || len(*res.Assertions) != 1 {
		t.Fatalf("Assertions = %#v, want one", res.Assertions)
	}
	trace := strings.Join((*res.Assertions)[0].Trace, "\n")
	if !strings.Contains(trace, "acl 0: could not evaluate: destination could not be parsed") {
		t.Errorf("trace = %q, want it to name the parse failure", trace)
	}
	if strings.Contains(trace, "acl 0: destination or port did not match") {
		t.Errorf("trace = %q, must not report a parse failure as a semantic non-match", trace)
	}
}

func TestPolicyTestIndeterminateExitPolicy(t *testing.T) {
	t.Parallel()
	const policy = `{
		"grants": [{"src": ["alice@example.com"], "dst": ["tag:web"], "ip": ["tpc:443"]}],
		"tests": [{"src": "alice@example.com", "deny": ["tag:web:443"]}]
	}`
	testCases := []struct {
		mode string
		want int
	}{
		{indeterminateFail, exitFailed},
		{indeterminateWarn, exitIndeterminate},
		{indeterminateIgnore, exitOK},
	}
	for _, testCase := range testCases {
		t.Run(testCase.mode, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "acl.hujson")
			writeTestPolicy(t, path, policy)
			var stdout, stderr strings.Builder
			err := run(
				context.Background(),
				[]string{
					"--indeterminate=" + testCase.mode,
					"-format", "json",
					"--file", path,
					"test",
				},
				func(string) string { return "" },
				http.DefaultClient,
				"",
				&stdout,
				&stderr,
			)
			if code := exitCode(err); code != testCase.want {
				t.Fatalf("exit code = %d, want %d (error %v)", code, testCase.want, err)
			}
			var res result
			if err = json.Unmarshal([]byte(stdout.String()), &res); err != nil {
				t.Fatalf("stdout is not valid JSON: %v\n%s", err, stdout.String())
			}
			if res.Status != statusIndeterminate ||
				res.TestSummary == nil ||
				res.TestSummary.Indeterminate != 1 ||
				res.Assertions == nil ||
				(*res.Assertions)[0].Status != aclpolicy.AssertionIndeterminate {
				t.Errorf("result = %#v, want the indeterminate finding preserved", res)
			}
			if len(res.Skipped) != 1 || res.Skipped[0].Value != "tpc:443" {
				t.Errorf("Skipped = %#v, want the unknown protocol in every mode", res.Skipped)
			}
			if !strings.Contains(stderr.String(), "skipping unparseable policy rule") {
				t.Errorf("stderr = %q, want the warning preserved in every mode", stderr.String())
			}
		})
	}
}

func TestPolicyTestFailureOutranksIndeterminateMode(t *testing.T) {
	t.Parallel()
	const policy = `{
		"grants": [{"src": ["alice@example.com"], "dst": ["tag:web"], "ip": ["tpc:443"]}],
		"tests": [{
			"src": "alice@example.com",
			"accept": ["tag:other:443"],
			"deny": ["tag:web:443"]
		}]
	}`
	for _, mode := range []string{indeterminateFail, indeterminateWarn, indeterminateIgnore} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "acl.hujson")
			writeTestPolicy(t, path, policy)
			var stdout strings.Builder
			err := run(
				context.Background(),
				[]string{
					"--indeterminate=" + mode,
					"-format", "json",
					"--file", path,
					"test",
				},
				func(string) string { return "" },
				http.DefaultClient,
				"",
				&stdout,
				io.Discard,
			)
			if code := exitCode(err); code != exitFailed {
				t.Fatalf("exit code = %d, want %d (error %v)", code, exitFailed, err)
			}
			var res result
			if err = json.Unmarshal([]byte(stdout.String()), &res); err != nil {
				t.Fatalf("stdout is not valid JSON: %v\n%s", err, stdout.String())
			}
			if res.Status != statusFailed ||
				res.TestSummary == nil ||
				res.TestSummary.Failed != 1 ||
				res.TestSummary.Indeterminate != 1 {
				t.Errorf("result = %#v, want a failure outranking one indeterminate assertion", res)
			}
		})
	}
}

func TestIndeterminateFlagIsTestOnly(t *testing.T) {
	t.Parallel()
	err := run(
		context.Background(),
		[]string{"--indeterminate=ignore", "check"},
		func(string) string { return "" },
		http.DefaultClient,
		"",
		io.Discard,
		io.Discard,
	)
	if code := exitCode(err); code != exitUsage {
		t.Fatalf("exit code = %d, want %d (error %v)", code, exitUsage, err)
	}
	if !strings.Contains(err.Error(), "applies only to test") {
		t.Errorf("error = %v, want the test-only scope explained", err)
	}
}

// Calling the flag "test only" invites writing it after the subcommand, where
// the root FlagSet never sees it. Say which position is meant rather than
// reporting it as a stray argument.
func TestIndeterminateFlagAfterSubcommandExplainsPosition(t *testing.T) {
	t.Parallel()
	for _, arg := range []string{"--indeterminate=fail", "-indeterminate", "--indeterminate"} {
		t.Run(arg, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "acl.hujson")
			writeTestPolicy(t, path, `{"tests": []}`)
			err := run(
				context.Background(),
				[]string{"--file", path, "test", arg},
				func(string) string { return "" },
				http.DefaultClient,
				"",
				io.Discard,
				io.Discard,
			)
			if code := exitCode(err); code != exitUsage {
				t.Fatalf("exit code = %d, want %d (error %v)", code, exitUsage, err)
			}
			if !strings.Contains(err.Error(), "is a global flag") {
				t.Errorf("error = %v, want the flag position explained", err)
			}
		})
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
			"--dst", "tag:db:5432", "--proto", "icmp",
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
	// sctp is queryable: Tailscale's packet filter matches it by port, so the
	// CLI must accept it rather than rejecting it alongside icmp.
	if err = run(
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
	); exitCode(err) == exitUsage {
		t.Fatalf("--proto sctp was rejected: %v", err)
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
		"typed edits preserve comments in JSON and HuJSON",
		"tail-acl --file acl.hujson tag-owner add tag:web autogroup:admin  # comments preserved",
		"check --src alice@example.com --dst tag:web:443",
		"Statically lint policy hygiene (dead grants, undefined refs, over-broad *)",
		"# static policy hygiene findings",
		"0  success; check reports reachable",
		"1  operation or policy assertion failed; check reports not reachable",
		"2  usage, input, or collection error",
		"10 indeterminate",
		"Also returned by",
		"test only: indeterminate assertion exit policy: fail|warn|ignore",
		"Server-side validate is the only check that catches an unreadable port or",
		"--indeterminate does not weaken check's verdict",
		"--proto sctp",
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
		Flags        []schemaFlag          `json:"flags"`
		Commands     []schemaCommand       `json:"commands"`
		Capabilities schemaCapabilities    `json:"capabilities"`
		LintFindings []aclpolicy.LintCheck `json:"lint_findings"`
		ExitCodes    map[string]string     `json:"exit_codes"`
	}
	if err := json.Unmarshal([]byte(stdout.String()), &doc); err != nil {
		t.Fatalf("schema is not valid JSON: %v\n%s", err, stdout.String())
	}
	if doc.Name != "tail-acl" || len(doc.Commands) == 0 || doc.ExitCodes["2"] == "" {
		t.Errorf("schema = %#v", doc)
	}
	if !slices.ContainsFunc(doc.Flags, func(schemaFlag schemaFlag) bool {
		return schemaFlag.Name == "indeterminate" &&
			schemaFlag.Default == indeterminateWarn &&
			strings.Contains(schemaFlag.Usage, "test only")
	}) {
		t.Errorf("schema flags = %#v, want test-only --indeterminate with default warn", doc.Flags)
	}
	if !slices.Equal(doc.Capabilities.TypedEdits.Formats, []string{"json", "hujson"}) ||
		!doc.Capabilities.TypedEdits.PreservesComments || !doc.Capabilities.TypedEdits.AuthorsComments {
		t.Errorf("schema typed edit capabilities = %#v", doc.Capabilities.TypedEdits)
	}
	// Comment authoring is expressed once as a capability, but an agent reading
	// the catalog still has to see the flag on every command that accepts it.
	for _, name := range []string{commandGrantAdd, commandTagOwnerAdd, commandHostSet, commandPostureSet} {
		if !slices.ContainsFunc(doc.Commands, func(command schemaCommand) bool {
			return command.Name == name && strings.Contains(command.Usage, "[--comment TEXT]")
		}) {
			t.Errorf("schema usage for %q is missing [--comment TEXT]: %#v", name, doc.Commands)
		}
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
	if !slices.ContainsFunc(
		doc.Commands,
		func(command schemaCommand) bool { return command.Name == commandPostureSet },
	) {
		t.Errorf("schema commands = %#v, want %q", doc.Commands, commandPostureSet)
	}
	if !slices.ContainsFunc(
		doc.Commands,
		func(command schemaCommand) bool { return command.Name == commandPostureRemove },
	) {
		t.Errorf("schema commands = %#v, want %q", doc.Commands, commandPostureRemove)
	}
}

func TestIndeterminateFlagRejectsUnknownMode(t *testing.T) {
	t.Parallel()
	err := run(
		context.Background(),
		[]string{"--indeterminate=maybe", "test"},
		func(string) string { return "" },
		http.DefaultClient,
		"",
		io.Discard,
		io.Discard,
	)
	if code := exitCode(err); code != exitUsage {
		t.Fatalf("exit code = %d, want %d (error %v)", code, exitUsage, err)
	}
	if !strings.Contains(err.Error(), "fail, warn, or ignore") {
		t.Errorf("error = %v, want the accepted modes", err)
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

// NDJSON is render's JSON branch minus SetIndent. Assert the shape a consumer
// depends on: one complete envelope per line, each independently parseable.
func TestStreamEmitterJSONIsNDJSON(t *testing.T) {
	t.Parallel()
	var out strings.Builder
	emitter := newStreamEmitter(&out, formatJSON)
	for _, message := range []string{"first", "second"} {
		if err := emitter.emit(newResult(cmdTest, statusOK, message)); err != nil {
			t.Fatalf("emit: %v", err)
		}
	}
	lines := strings.Split(strings.TrimSuffix(out.String(), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("lines = %d, want 2: %q", len(lines), out.String())
	}
	for i, line := range lines {
		var envelope result
		if err := json.Unmarshal([]byte(line), &envelope); err != nil {
			t.Errorf("line %d does not parse on its own: %v (%q)", i, err, line)
		}
	}
	if strings.Contains(out.String(), "\n  ") {
		t.Errorf("NDJSON is indented, so lines are not independently parseable:\n%s", out.String())
	}
}

func TestStreamEmitterHumanSeparatesRunsWithOneBlankLine(t *testing.T) {
	t.Parallel()
	var out strings.Builder
	emitter := newStreamEmitter(&out, formatHuman)
	for _, message := range []string{"first", "second"} {
		if err := emitter.emit(newResult(cmdTest, statusOK, message)); err != nil {
			t.Fatalf("emit: %v", err)
		}
	}
	const want = "tail-acl: first\n\ntail-acl: second\n"
	if out.String() != want {
		t.Errorf("output = %q, want %q", out.String(), want)
	}
}

// The compatibility guard for AC "non-watch -format json is byte-identical to
// today": a new omitempty field must not appear, and indentation must remain.
func TestSingleShotJSONStaysIndentedWithoutPolicyDigest(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.hujson")
	writeTestPolicy(t, path, `{"tests": []}`)
	var stdout, stderr strings.Builder
	if err := run(
		context.Background(),
		[]string{"--file", path, "-format", formatJSON, cmdTest},
		func(string) string { return "" },
		http.DefaultClient,
		"",
		&stdout,
		&stderr,
	); err != nil {
		t.Fatalf("run: %v", err)
	}
	if !strings.Contains(stdout.String(), "\n  \"tool\": \"tail-acl\"") {
		t.Errorf("single-shot JSON lost its indentation:\n%s", stdout.String())
	}
	if strings.Contains(stdout.String(), "policy_digest") {
		t.Errorf("single-shot JSON gained a policy_digest key:\n%s", stdout.String())
	}
}

const watchPassingPolicy = `{
	"grants": [{"src": ["group:dev"], "dst": ["tag:web"], "ip": ["tcp:443"]}],
	"groups": {"group:dev": ["alice@example.com"]},
	"tests": [{"src": "alice@example.com", "accept": ["tag:web:443"]}]
}`

const watchFailingPolicy = `{
	"grants": [{"src": ["alice@example.com"], "dst": ["tag:web"], "ip": ["tcp:443"]}],
	"tests": [{"src": "alice@example.com", "deny": ["tag:web:443"]}]
}`

// watchDriver is an [io.Writer] that drives the loop instead of a sleep. The watch
// loop has no synchronous "iteration finished" signal, so the test reacts to
// each completed record as it is written: edit the file after run 1, cancel
// after run 2. Writes happen on the same goroutine as run, so the loop is
// blocked inside emit while step executes and nothing races.
type watchDriver struct {
	marker string
	buf    strings.Builder
	seen   int
	step   func(run int)
}

func (d *watchDriver) Write(p []byte) (int, error) {
	n, err := d.buf.Write(p)
	if runs := strings.Count(d.buf.String(), d.marker); runs > d.seen {
		d.seen = runs
		if d.step != nil {
			d.step(runs)
		}
	}
	return n, err
}

func (d *watchDriver) String() string { return d.buf.String() }

func (d *watchDriver) records() []string {
	trimmed := strings.TrimSuffix(d.buf.String(), "\n")
	if trimmed == "" {
		return nil
	}
	return strings.Split(trimmed, "\n")
}

// runWatch invokes run in watch mode with a hard ceiling, so a loop that never
// emits fails with a readable assertion instead of hanging until the go test
// timeout.
func runWatch(t *testing.T, path, format string, stdout io.Writer, stderr io.Writer) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return run(
		ctx,
		[]string{"--file", path, "-format", format, cmdTest, "--watch", "--interval", "1ms"},
		func(string) string { return "" },
		http.DefaultClient,
		"",
		stdout,
		stderr,
	)
}

// runWatchCancellable covers the cases that cancel themselves through a
// [context.CancelFunc] the test closes over.
func runWatchCancellable(
	t *testing.T,
	path, format string,
	stdout, stderr io.Writer,
	arm func(cancel context.CancelFunc),
) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	arm(cancel)
	return run(
		ctx,
		[]string{"--file", path, "-format", format, cmdTest, "--watch", "--interval", "1ms"},
		func(string) string { return "" },
		http.DefaultClient,
		"",
		stdout,
		stderr,
	)
}

func TestWatchRerunsOnChange(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.hujson")
	writeTestPolicy(t, path, watchPassingPolicy)
	driver := &watchDriver{marker: "}\n"}
	var stderr strings.Builder

	err := runWatchCancellable(t, path, formatJSON, driver, &stderr, func(cancel context.CancelFunc) {
		driver.step = func(run int) {
			switch run {
			case 1:
				writeTestPolicy(t, path, watchFailingPolicy)
			case 2:
				cancel()
			}
		}
	})
	if code := exitCode(err); code != exitOK {
		t.Fatalf("exit code = %d, want %d (error %v)", code, exitOK, err)
	}
	records := driver.records()
	if len(records) != 2 {
		t.Fatalf("records = %d, want 2:\n%s", len(records), driver)
	}
	var first, second result
	if unmarshalErr := json.Unmarshal([]byte(records[0]), &first); unmarshalErr != nil {
		t.Fatalf("record 0: %v", unmarshalErr)
	}
	if unmarshalErr := json.Unmarshal([]byte(records[1]), &second); unmarshalErr != nil {
		t.Fatalf("record 1: %v", unmarshalErr)
	}
	if first.Status != statusOK || second.Status != statusFailed {
		t.Errorf("statuses = %q then %q, want %q then %q",
			first.Status, second.Status, statusOK, statusFailed)
	}
	if first.PolicyDigest == second.PolicyDigest {
		t.Errorf("both runs reported digest %q; the edit was not correlated", first.PolicyDigest)
	}
}

func TestWatchJSONIsNDJSON(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.hujson")
	writeTestPolicy(t, path, watchPassingPolicy)
	driver := &watchDriver{marker: "}\n"}
	var stderr strings.Builder

	err := runWatchCancellable(t, path, formatJSON, driver, &stderr, func(cancel context.CancelFunc) {
		driver.step = func(int) { cancel() }
	})
	if code := exitCode(err); code != exitOK {
		t.Fatalf("exit code = %d, want %d (error %v)", code, exitOK, err)
	}
	if strings.Contains(driver.String(), "\n  ") {
		t.Errorf("watch JSON is indented, so lines are not independently parseable:\n%s", driver)
	}
	records := driver.records()
	if len(records) == 0 {
		t.Fatal("no records emitted")
	}
	want := watchDigest(t, watchPassingPolicy)
	for i, record := range records {
		var envelope result
		if unmarshalErr := json.Unmarshal([]byte(record), &envelope); unmarshalErr != nil {
			t.Fatalf("record %d does not parse on its own: %v (%q)", i, unmarshalErr, record)
		}
		if envelope.PolicyDigest != want {
			t.Errorf("record %d digest = %q, want %q", i, envelope.PolicyDigest, want)
		}
	}
}

// watchDigest recomputes the digest independently of the implementation, so the
// test pins the value rather than echoing whatever the tool produced.
func watchDigest(t *testing.T, document string) string {
	t.Helper()
	sum := sha256.Sum256([]byte(document))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func TestWatchIgnoresIdenticalRewrite(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.hujson")
	writeTestPolicy(t, path, watchPassingPolicy)
	driver := &watchDriver{marker: "}\n"}
	var stderr strings.Builder

	err := runWatchCancellable(t, path, formatJSON, driver, &stderr, func(cancel context.CancelFunc) {
		driver.step = func(run int) {
			if run == 1 {
				writeTestPolicy(t, path, watchPassingPolicy)
				// Absence of a second run is the assertion, so let the loop tick
				// many times over these bytes before stopping it.
				time.AfterFunc(100*time.Millisecond, cancel)
			}
		}
	})
	if code := exitCode(err); code != exitOK {
		t.Fatalf("exit code = %d, want %d (error %v)", code, exitOK, err)
	}
	if records := driver.records(); len(records) != 1 {
		t.Errorf("records = %d, want 1 — identical bytes re-ran the suite:\n%s", len(records), driver)
	}
}

func TestWatchSurvivesAtomicRename(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "acl.hujson")
	writeTestPolicy(t, path, watchPassingPolicy)
	driver := &watchDriver{marker: "}\n"}
	var stderr strings.Builder

	err := runWatchCancellable(t, path, formatJSON, driver, &stderr, func(cancel context.CancelFunc) {
		driver.step = func(run int) {
			switch run {
			case 1:
				// The replacement every editor and aclpolicy.WriteRaw performs.
				staged := filepath.Join(dir, "acl.hujson.tmp")
				writeTestPolicy(t, staged, watchFailingPolicy)
				if err := os.Rename(staged, path); err != nil {
					t.Errorf("rename: %v", err)
					cancel()
				}
			case 2:
				cancel()
			}
		}
	})
	if code := exitCode(err); code != exitOK {
		t.Fatalf("exit code = %d, want %d (error %v)", code, exitOK, err)
	}
	if records := driver.records(); len(records) != 2 {
		t.Errorf("records = %d, want 2 — the rename was not detected:\n%s", len(records), driver)
	}
}

func TestWatchSurvivesUnparseableFile(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.hujson")
	writeTestPolicy(t, path, watchPassingPolicy)
	driver := &watchDriver{marker: "}\n"}
	// slog's TextHandler writes one record per Write, so the stderr driver turns
	// "the warning was logged" into a signal — no sleep needed to repair the file.
	logs := &watchDriver{marker: "\n"}

	err := runWatchCancellable(t, path, formatJSON, driver, logs, func(cancel context.CancelFunc) {
		driver.step = func(run int) {
			switch run {
			case 1:
				writeTestPolicy(t, path, `{"grants": [`)
			case 2:
				cancel()
			}
		}
		logs.step = func(logged int) {
			if logged == 1 {
				writeTestPolicy(t, path, watchFailingPolicy)
			}
		}
	})
	if code := exitCode(err); code != exitOK {
		t.Fatalf("exit code = %d, want %d (error %v)", code, exitOK, err)
	}
	records := driver.records()
	if len(records) != 2 {
		t.Fatalf("records = %d, want 2 (broken save emits nothing, repair resumes):\n%s",
			len(records), driver)
	}
	for i, record := range records {
		var envelope result
		if unmarshalErr := json.Unmarshal([]byte(record), &envelope); unmarshalErr != nil {
			t.Errorf("record %d does not parse: %v (%q)", i, unmarshalErr, record)
		}
	}
	if !strings.Contains(logs.String(), "did not produce a verdict") {
		t.Errorf("stderr never explained the broken save:\n%s", logs)
	}
}

func TestWatchLogsBrokenFileOnce(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.hujson")
	// Readable but unparseable: startup succeeds, every evaluation fails.
	writeTestPolicy(t, path, `{"grants": [`)
	var stdout strings.Builder
	logs := &watchDriver{marker: "\n"}

	err := runWatchCancellable(t, path, formatJSON, &stdout, logs, func(cancel context.CancelFunc) {
		logs.step = func(int) { time.AfterFunc(100*time.Millisecond, cancel) }
	})
	if code := exitCode(err); code != exitOK {
		t.Fatalf("exit code = %d, want %d (error %v)", code, exitOK, err)
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout = %q, want nothing for a file that produced no verdict", stdout.String())
	}
	if got := strings.Count(logs.String(), "did not produce a verdict"); got != 1 {
		t.Errorf("logged the same broken file %d times, want 1:\n%s", got, logs)
	}
}

func TestWatchAlwaysExitsZero(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.hujson")
	writeTestPolicy(t, path, watchFailingPolicy)
	driver := &watchDriver{marker: "}\n"}
	var stderr strings.Builder

	err := runWatchCancellable(t, path, formatJSON, driver, &stderr, func(cancel context.CancelFunc) {
		driver.step = func(int) { cancel() }
	})
	if code := exitCode(err); code != exitOK {
		t.Fatalf("exit code = %d, want %d — interrupting a red suite is not a verdict (error %v)",
			code, exitOK, err)
	}
	var envelope result
	if unmarshalErr := json.Unmarshal([]byte(driver.records()[0]), &envelope); unmarshalErr != nil {
		t.Fatalf("record 0: %v", unmarshalErr)
	}
	if envelope.Status != statusFailed {
		t.Errorf("status = %q, want %q — exit 0 must not hide the red verdict",
			envelope.Status, statusFailed)
	}
}

func TestWatchHumanSeparatesRunsAndEmitsNoANSI(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.hujson")
	writeTestPolicy(t, path, watchPassingPolicy)
	driver := &watchDriver{marker: "tail-acl: "}
	var stderr strings.Builder

	err := runWatchCancellable(t, path, formatHuman, driver, &stderr, func(cancel context.CancelFunc) {
		driver.step = func(run int) {
			switch run {
			case 1:
				writeTestPolicy(t, path, watchFailingPolicy)
			case 2:
				cancel()
			}
		}
	})
	if code := exitCode(err); code != exitOK {
		t.Fatalf("exit code = %d, want %d (error %v)", code, exitOK, err)
	}
	if strings.Contains(driver.String(), "\x1b") {
		t.Errorf("stdout contains an ANSI escape:\n%q", driver.String())
	}
	if !strings.Contains(driver.String(), "\n\ntail-acl: ") &&
		!strings.Contains(driver.String(), "\n\nFAIL ") &&
		!strings.Contains(driver.String(), "\n\nPASS ") {
		t.Errorf("runs are not separated by a blank line:\n%s", driver)
	}
}

func TestWatchUnreadableFileAtStartupIsExitTwo(t *testing.T) {
	t.Parallel()
	var stdout, stderr strings.Builder
	err := runWatch(t, filepath.Join(t.TempDir(), "missing.hujson"), formatJSON, &stdout, &stderr)
	if code := exitCode(err); code != exitUsage {
		t.Fatalf("exit code = %d, want %d (error %v)", code, exitUsage, err)
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout = %q, want nothing", stdout.String())
	}
}

func TestWatchRejectsNonPositiveInterval(t *testing.T) {
	t.Parallel()
	for _, interval := range []string{"0", "-1ms"} {
		t.Run(interval, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "acl.hujson")
			writeTestPolicy(t, path, watchPassingPolicy)
			var stdout, stderr strings.Builder
			err := run(
				context.Background(),
				[]string{"--file", path, cmdTest, "--watch", "--interval", interval},
				func(string) string { return "" },
				http.DefaultClient,
				"",
				&stdout,
				&stderr,
			)
			if code := exitCode(err); code != exitUsage {
				t.Fatalf("exit code = %d, want %d (error %v)", code, exitUsage, err)
			}
		})
	}
}

func TestWatchRejectsIndeterminate(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.hujson")
	writeTestPolicy(t, path, watchPassingPolicy)
	var stdout, stderr strings.Builder
	err := run(
		context.Background(),
		[]string{"--indeterminate=fail", "--file", path, cmdTest, "--watch"},
		func(string) string { return "" },
		http.DefaultClient,
		"",
		&stdout,
		&stderr,
	)
	if code := exitCode(err); code != exitUsage {
		t.Fatalf("exit code = %d, want %d (error %v)", code, exitUsage, err)
	}
	if !strings.Contains(err.Error(), "never exits non-zero") {
		t.Errorf("error = %v, want it to explain why the flag is inert", err)
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout = %q, want nothing", stdout.String())
	}
}

func TestIntervalWithoutWatchIsRejected(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.hujson")
	writeTestPolicy(t, path, watchPassingPolicy)
	var stdout, stderr strings.Builder
	err := run(
		context.Background(),
		[]string{"--file", path, cmdTest, "--interval", "1s"},
		func(string) string { return "" },
		http.DefaultClient,
		"",
		&stdout,
		&stderr,
	)
	if code := exitCode(err); code != exitUsage {
		t.Fatalf("exit code = %d, want %d (error %v)", code, exitUsage, err)
	}
	if !strings.Contains(err.Error(), "--interval applies only to --watch") {
		t.Errorf("error = %v, want it to name the missing --watch", err)
	}
}

func TestPlainTestStillRunsWithTheDefaultInterval(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.hujson")
	writeTestPolicy(t, path, watchPassingPolicy)
	var stdout, stderr strings.Builder
	if err := run(
		context.Background(),
		[]string{"--file", path, cmdTest},
		func(string) string { return "" },
		http.DefaultClient,
		"",
		&stdout,
		&stderr,
	); err != nil {
		t.Fatalf("run: %v", err)
	}
	if !strings.Contains(stdout.String(), "1 assertions: 1 passed, 0 failed") {
		t.Errorf("stdout = %q, want the ordinary single-shot verdict", stdout.String())
	}
}

func TestSchemaAndUsageDocumentWatch(t *testing.T) {
	t.Parallel()
	for _, testCase := range []struct {
		name      string
		args      []string
		fragments []string
	}{
		{
			name:      "schema",
			args:      []string{"-schema"},
			fragments: []string{"--watch", "--interval"},
		},
		{
			name:      "help",
			args:      []string{"--help"},
			fragments: []string{"--watch", "never exits non-zero"},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			var stdout, stderr strings.Builder
			err := run(
				context.Background(),
				testCase.args,
				func(string) string { return "" },
				http.DefaultClient,
				"",
				&stdout,
				&stderr,
			)
			if err != nil && !errors.Is(err, flag.ErrHelp) {
				t.Fatalf("run: %v", err)
			}
			// -schema writes to stdout; --help writes usage to stderr.
			combined := stdout.String() + stderr.String()
			for _, fragment := range testCase.fragments {
				if !strings.Contains(combined, fragment) {
					t.Errorf("output missing %q:\n%s", fragment, combined)
				}
			}
		})
	}
}

func TestSchemaExitCode2MentionsWatch(t *testing.T) {
	t.Parallel()
	var stdout, stderr strings.Builder
	err := run(
		context.Background(),
		[]string{"-schema"},
		func(string) string { return "" },
		http.DefaultClient,
		"",
		&stdout,
		&stderr,
	)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	var doc map[string]any
	if unmarshalErr := json.Unmarshal([]byte(stdout.String()), &doc); unmarshalErr != nil {
		t.Fatalf("parse schema JSON: %v", unmarshalErr)
	}
	exitCodes, ok := doc["exit_codes"].(map[string]any)
	if !ok {
		t.Fatalf("exit_codes field is not a map")
	}
	exitCode2, ok := exitCodes["2"].(string)
	if !ok {
		t.Fatalf("exit_codes[\"2\"] is not a string")
	}
	for _, fragment := range []string{"test --watch", "unreadable --file", "failed write"} {
		if !strings.Contains(exitCode2, fragment) {
			t.Errorf("exit_codes[\"2\"] missing %q:\n%s", fragment, exitCode2)
		}
	}
}

// failingWriter stands in for a write that returns an error, such as a full
// disk. It is not a closed pipe: on Unix, writing to a closed reader on real
// stdout (`tail-acl test --watch | head -1`) dies by SIGPIPE (exit 141) instead
// of returning an error, so that path never reaches watchTests at all — and it
// only reaches SIGPIPE on the next save, since nothing is written in between.
type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("no space left on device") }

// A failed write is the watcher's own failure, not a verdict, so it exits 2.
// Exit 1 would collide with "a policy assertion failed".
func TestWatchWriteFailureIsExitTwo(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.hujson")
	writeTestPolicy(t, path, watchPassingPolicy)
	var stderr strings.Builder
	err := runWatch(t, path, formatJSON, failingWriter{}, &stderr)
	if code := exitCode(err); code != exitUsage {
		t.Fatalf("exit code = %d, want %d (error %v)", code, exitUsage, err)
	}
}

// [signal.NotifyContext] cancels on the first interrupt and then stops relaying
// without unregistering, so without this the signal stays trapped and every
// later Ctrl-C is swallowed — leaving a command wedged in a syscall (a blocked
// write to a full pipe, merge over a slow mount) killable only by SIGKILL.
func TestRestoreDefaultAfterCancelReleasesTheSignalOnCancel(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	stopped := make(chan struct{})
	restoreDefaultAfterCancel(ctx, func() { close(stopped) })

	select {
	case <-stopped:
		t.Fatal("released the signal before the first interrupt; Ctrl-C would not cancel at all")
	case <-time.After(50 * time.Millisecond):
	}

	cancel()
	select {
	case <-stopped:
	case <-time.After(10 * time.Second):
		t.Fatal("never released the signal, so a second Ctrl-C cannot kill a wedged command")
	}
}

// An interrupt is a collection failure, not a verdict. Exit 1 would report a
// definite failure for an upload whose request may already have been applied.
func TestInterruptedRequestIsExitTwo(t *testing.T) {
	t.Parallel()
	for _, testCase := range []struct {
		name string
		err  error
	}{
		{"upload", fmt.Errorf("uploading %s: %w", "acl.json", context.Canceled)},
		{"plan", fmt.Errorf("fetching deployed policy: %w", context.Canceled)},
		{"bare", context.Canceled},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			if code := exitCode(testCase.err); code != exitUsage {
				t.Errorf("exitCode(%v) = %d, want %d", testCase.err, code, exitUsage)
			}
		})
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
