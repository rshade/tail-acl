package main

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/rshade/tailscale-utils/tail-acl/internal/aclpolicy"
)

// commentAuthoringPolicy carries a comment in each position that decides
// attribution: one on the opening brace, one trailing a member on its own line
// (tag:web), one leading a member (hosts.legacy), and an unedited tail.
const commentAuthoringPolicy = `{
	// Owner: platform-team. Do not hand-edit without review.
	"tagOwners": {
		"tag:web": ["group:ops"], // web front ends
		"tag:db":  ["autogroup:admin"],
	},
	"hosts": {
		// Legacy monitoring endpoint
		"legacy": "100.64.0.9",
	},
	"postures": {
		"posture:keep": ["custom:keep == true"],
	},
	"grants": [
		{"src": ["group:keep"], "dst": ["tag:db"], "ip": ["tcp:5432"]},
	],
	"groups": {
		"group:a": ["a@example.com"], // this block is never edited
	},
}
`

// commentTarget names an authoring command and the node its comment must land
// on, so a test asserts placement rather than mere presence.
type commentTarget struct {
	name     string
	command  []string
	segments []string
}

func authoringTargets() []commentTarget {
	return []commentTarget{
		{
			commandGrantAdd,
			[]string{"grant", "add", "--src", "tag:app", "--dst", "tag:db", "--ip", "tcp:5432"},
			[]string{"grants", "-"},
		},
		{
			commandTagOwnerAdd,
			[]string{"tag-owner", "add", "tag:web", "group:platform"},
			[]string{"tagOwners", "tag:web", "-"},
		},
		{commandHostSet, []string{"host", "set", "web", "100.64.0.10"}, []string{"hosts", "web"}},
		{
			commandPostureSet,
			[]string{"posture", "set", "posture:lab", "custom:labCompliant == true"},
			[]string{"postures", "posture:lab"},
		},
		{
			commandAutoApproverAdd,
			[]string{"auto-approver", "add", "--route", "10.0.0.0/8", "--approver", "group:platform"},
			[]string{"autoApprovers", "routes", "10.0.0.0/8"},
		},
		{
			commandGroupAdd,
			[]string{"group", "add", "--name", "group:a", "--member", "platform@example.com"},
			[]string{"groups", "group:a"},
		},
		{
			commandIPSetAdd,
			[]string{"ipset", "add", "--name", "ipset:office", "--cidr", "10.0.0.0/8"},
			[]string{"ipsets", "ipset:office"},
		},
		{
			commandSSHAdd,
			[]string{"ssh", "add", "--action", "accept", "--src", "tag:app", "--dst", "tag:db", "--user", "root"},
			[]string{"ssh", "-"},
		},
		{
			commandNodeAttrAdd,
			[]string{"nodeattr", "add", "--target", "tag:app", "--attr", "funnel"},
			[]string{"nodeAttrs", "-"},
		},
		{
			commandExternalTailnetAdd,
			[]string{"external-tailnet", "add", "partner", "--external-id", "tn-123"},
			[]string{"externalTailnets", "partner"},
		},
	}
}

func TestTypedEditsAuthorComments(t *testing.T) {
	t.Parallel()
	const comment = "Owned by platform; see #59"
	for _, target := range authoringTargets() {
		for _, extension := range []string{".json", ".hujson"} {
			t.Run(target.name+extension, func(t *testing.T) {
				t.Parallel()
				path := filepath.Join(t.TempDir(), "acl"+extension)
				writeTestPolicy(t, path, commentAuthoringPolicy)

				command := append(slices.Clone(target.command), "--comment", comment)
				if _, err := runTailACL(t, path, command...); err != nil {
					t.Fatalf("run(%q): %v", command, err)
				}

				assertCommentsOn(t, path, []string{comment}, target.segments...)
				output := readPolicy(t, path)
				for _, preserved := range []string{
					"// Owner: platform-team. Do not hand-edit without review.",
					"// web front ends",
					"// Legacy monitoring endpoint",
					"// this block is never edited",
				} {
					if !strings.Contains(output, preserved) {
						t.Errorf("%s lost %q:\n%s", target.name, preserved, output)
					}
				}
				assertPolicyKeyOrder(t, output, "tagOwners", "hosts", "postures", "grants", "groups")
				if _, err := aclpolicy.Load(path); err != nil {
					t.Errorf("commented policy no longer loads: %v\n%s", err, output)
				}
			})
		}
	}
}

func TestCommentAuthoringIsIdempotent(t *testing.T) {
	t.Parallel()
	const comment = "Reviewed 2026-07-30"
	for _, target := range authoringTargets() {
		t.Run(target.name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "acl.hujson")
			writeTestPolicy(t, path, commentAuthoringPolicy)
			command := append(slices.Clone(target.command), "--comment", comment)

			if _, err := runTailACL(t, path, command...); err != nil {
				t.Fatalf("first run: %v", err)
			}
			first := readPolicy(t, path)

			stdout, err := runTailACL(t, path, command...)
			if err != nil {
				t.Fatalf("second run: %v", err)
			}
			if status := decodeStatus(t, stdout); status != statusNoChanges {
				t.Errorf("second run status = %q, want %q", status, statusNoChanges)
			}
			second := readPolicy(t, path)
			if first != second {
				t.Errorf("second run changed the file:\nfirst:\n%s\nsecond:\n%s", first, second)
			}
			if count := strings.Count(second, "// "+comment); count != 1 {
				t.Errorf("comment appears %d times, want 1:\n%s", count, second)
			}
		})
	}
}

// A value that already exists plus a comment that does not is a real change:
// reporting no_changes would tell the operator their note was recorded when it
// was not.
func TestCommentOnExistingValueReportsChange(t *testing.T) {
	t.Parallel()
	const comment = "Kept deliberately"
	testCases := []commentTarget{
		{
			commandGrantAdd,
			[]string{"grant", "add", "--src", "group:keep", "--dst", "tag:db", "--ip", "tcp:5432"},
			[]string{"grants", "0"},
		},
		{
			commandTagOwnerAdd,
			[]string{"tag-owner", "add", "tag:web", "group:ops"},
			[]string{"tagOwners", "tag:web", "0"},
		},
		{commandHostSet, []string{"host", "set", "legacy", "100.64.0.9"}, []string{"hosts", "legacy"}},
		{
			commandPostureSet,
			[]string{"posture", "set", "posture:keep", "custom:keep == true"},
			[]string{"postures", "posture:keep"},
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "acl.hujson")
			writeTestPolicy(t, path, commentAuthoringPolicy)

			command := append(slices.Clone(testCase.command), "--comment", comment)
			stdout, err := runTailACL(t, path, command...)
			if err != nil {
				t.Fatalf("run(%q): %v", command, err)
			}
			if status := decodeStatus(t, stdout); status != statusOK {
				t.Errorf("status = %q, want %q", status, statusOK)
			}

			policy, loadErr := aclpolicy.Load(path)
			if loadErr != nil {
				t.Fatalf("policy no longer loads: %v\n%s", loadErr, readPolicy(t, path))
			}
			if len(policy.Grants) != 1 || len(policy.TagOwners["tag:web"]) != 1 {
				t.Errorf("commenting duplicated a value: grants=%d tag:web owners=%v",
					len(policy.Grants), policy.TagOwners["tag:web"])
			}
			if !slices.Contains(commentsOn(t, path, testCase.segments...), comment) {
				t.Errorf("comment did not land on %v:\n%s", testCase.segments, readPolicy(t, path))
			}
		})
	}
}

// hujson's own patch path would drop the existing note: injectLeadingComments
// truncates the slot before appending. Annotating the tree after the patch is
// what keeps the operator's text.
func TestCommentPreservesExistingLeadingComments(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.hujson")
	writeTestPolicy(t, path, commentAuthoringPolicy)

	if _, err := runTailACL(t, path, "host", "set", "legacy", "100.64.0.99",
		"--comment", "Now the canary"); err != nil {
		t.Fatal(err)
	}

	assertCommentsOn(t, path, []string{"Legacy monitoring endpoint", "Now the canary"}, "hosts", "legacy")
}

func TestOverwriteCommentReplacesExistingComments(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.hujson")
	writeTestPolicy(t, path, commentAuthoringPolicy)

	stdout, err := runTailACL(t, path, "host", "set", "legacy", "100.64.0.99",
		"--comment", "Now the canary", "--overwrite-comment")
	if err != nil {
		t.Fatal(err)
	}
	if status := decodeStatus(t, stdout); status != statusOK {
		t.Errorf("status = %q, want %q", status, statusOK)
	}

	assertCommentsOn(t, path, []string{"Now the canary"}, "hosts", "legacy")
	output := readPolicy(t, path)
	if strings.Contains(output, "Legacy monitoring endpoint") {
		t.Errorf("overwrite kept the replaced comment:\n%s", output)
	}
	if !strings.Contains(output, "// web front ends") {
		t.Errorf("overwrite reached outside the entry it targeted:\n%s", output)
	}

	// Repeating an overwrite must settle rather than rewrite.
	before := readPolicy(t, path)
	stdout, err = runTailACL(t, path, "host", "set", "legacy", "100.64.0.99",
		"--comment", "Now the canary", "--overwrite-comment")
	if err != nil {
		t.Fatal(err)
	}
	if status := decodeStatus(t, stdout); status != statusNoChanges {
		t.Errorf("repeat status = %q, want %q", status, statusNoChanges)
	}
	if after := readPolicy(t, path); after != before {
		t.Errorf("repeat rewrote the file:\n%s", after)
	}
}

// Doing nothing quietly would read as "the overwrite happened".
func TestOverwriteCommentRequiresComment(t *testing.T) {
	t.Parallel()
	for _, target := range authoringTargets() {
		t.Run(target.name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "acl.hujson")
			writeTestPolicy(t, path, commentAuthoringPolicy)

			command := append(slices.Clone(target.command), "--overwrite-comment")
			_, err := runTailACL(t, path, command...)
			if code := exitCode(err); code != exitUsage {
				t.Errorf("exit code = %d, want %d (error %v)", code, exitUsage, err)
			}
			assertFixtureUnchanged(t, path)
		})
	}
}

func TestCommentRejectsInvalidText(t *testing.T) {
	t.Parallel()
	invalid := map[string]string{
		"empty":           "",
		"whitespace only": "   ",
		"newline":         "first\nsecond",
		"carriage return": "first\rsecond",
		"invalid utf-8":   "bad \xff byte",
	}
	for _, target := range authoringTargets() {
		for name, text := range invalid {
			t.Run(target.name+" "+name, func(t *testing.T) {
				t.Parallel()
				path := filepath.Join(t.TempDir(), "acl.hujson")
				writeTestPolicy(t, path, commentAuthoringPolicy)

				command := append(slices.Clone(target.command), "--comment", text)
				_, err := runTailACL(t, path, command...)
				if code := exitCode(err); code != exitUsage {
					t.Errorf("exit code = %d, want %d (error %v)", code, exitUsage, err)
				}
				assertFixtureUnchanged(t, path)
			})
		}
	}
}

func TestCommentRejectedByUnsupportedCommands(t *testing.T) {
	t.Parallel()
	testCases := map[string][]string{
		"grant remove":   {"grant", "remove", "--index", "0", "--comment", "no"},
		"posture remove": {"posture", "remove", "posture:keep", "--comment", "no"},
		"check":          {"check", "--src", "tag:app", "--dst", "tag:db:5432", "--comment", "no"},
		"lint":           {"lint", "--comment", "no"},
		// The issue's opening example: there is no generic add command.
		"bare add": {"add", "--comment", "no"},
	}
	for name, command := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "acl.hujson")
			writeTestPolicy(t, path, commentAuthoringPolicy)

			_, err := runTailACL(t, path, command...)
			if code := exitCode(err); code != exitUsage {
				t.Errorf("exit code = %d, want %d (error %v)", code, exitUsage, err)
			}
			assertFixtureUnchanged(t, path)
		})
	}
}

// Posture expressions are opaque CLI arguments. Since posture set parses
// flags with pflag instead of a hand-rolled interspersed scanner, an argument
// beginning with "-" must follow a "--" terminator (POSIX Utility Syntax
// Guideline 10) to be treated as an expression at all; --comment must precede
// the terminator. Every valid expression starts with a node:/custom:/ip:
// namespace, so a dash-prefixed argument is never a valid expression — but
// the terminator still decides *which* rejection it gets: with it, the
// argument is validated as an expression and rejected as unparseable; without
// it, pflag rejects an unrecognized flag (see
// TestPostureSetRejectsUnrecognizedFlagWithoutTerminator).
func TestPostureSetDashPrefixedExpressionsNeedTerminator(t *testing.T) {
	t.Parallel()
	t.Run("negative operand", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(t.TempDir(), "acl.hujson")
		writeTestPolicy(t, path, commentAuthoringPolicy)

		_, err := runTailACL(t, path, "posture", "set", "posture:lab",
			"--comment", "allows negative scores", "--", "-1 < custom:score")
		if code := exitCode(err); code != exitUsage {
			t.Fatalf("exit code = %d, want %d (error %v)", code, exitUsage, err)
		}
		// The terminator did its job when the rejection is about the
		// expression, not about an unrecognized flag.
		if err == nil || !strings.Contains(err.Error(), "expression") {
			t.Errorf("error = %v, want an expression validation error", err)
		}
		assertFixtureUnchanged(t, path)
	})

	t.Run("flag-shaped expression", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(t.TempDir(), "acl.hujson")
		writeTestPolicy(t, path, commentAuthoringPolicy)

		_, err := runTailACL(t, path, "posture", "set", "posture:lab", "--", "--custom-check")
		if code := exitCode(err); code != exitUsage {
			t.Fatalf("exit code = %d, want %d (error %v)", code, exitUsage, err)
		}
		if err == nil || !strings.Contains(err.Error(), "expression") {
			t.Errorf("error = %v, want an expression validation error", err)
		}
		assertFixtureUnchanged(t, path)
	})

	t.Run("comment is not an expression", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(t.TempDir(), "acl.hujson")
		writeTestPolicy(t, path, commentAuthoringPolicy)

		if _, err := runTailACL(t, path, "posture", "set", "posture:lab",
			"custom:x == true", "--comment", "lab devices"); err != nil {
			t.Fatal(err)
		}
		policy, err := aclpolicy.Load(path)
		if err != nil {
			t.Fatal(err)
		}
		if want := []string{"custom:x == true"}; !slices.Equal(policy.Postures["posture:lab"], want) {
			t.Errorf("postures[posture:lab] = %q, want %q", policy.Postures["posture:lab"], want)
		}
	})
}

// Without a "--" terminator, a dash-prefixed expression that looks like a
// flag is now rejected as an unrecognized flag instead of silently becoming a
// positional and being written into the policy — a typo of --comment as
// --commnet used to corrupt the postures list this way with exit 0.
func TestPostureSetRejectsUnrecognizedFlagWithoutTerminator(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.hujson")
	writeTestPolicy(t, path, commentAuthoringPolicy)

	_, err := runTailACL(t, path, "posture", "set", "posture:lab",
		"custom:score > 1", "--commnet", "oops")
	if code := exitCode(err); code != exitUsage {
		t.Fatalf("exit code = %d, want %d (error %v)", code, exitUsage, err)
	}
	assertFixtureUnchanged(t, path)
}

func TestGrantCommentRejectsAmbiguousDuplicateGrant(t *testing.T) {
	t.Parallel()
	const policyText = `{
	"grants": [
		// First note
		{"src": ["group:a", "group:b"], "dst": ["tag:web"], "ip": ["tcp:443"]},
		// Second note
		{"src": ["group:b", "group:a"], "dst": ["tag:web"], "ip": ["tcp:443"]},
	],
}
`
	for _, overwrite := range []bool{false, true} {
		name := "append"
		if overwrite {
			name = "overwrite"
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "acl.hujson")
			writeTestPolicy(t, path, policyText)
			command := []string{
				"grant", "add",
				"--src", "group:a", "--src", "group:b",
				"--dst", "tag:web", "--ip", "tcp:443",
				"--comment", "Ambiguous note",
			}
			if overwrite {
				command = append(command, "--overwrite-comment")
			}

			_, err := runTailACL(t, path, command...)
			if err == nil || !strings.Contains(err.Error(), "duplicate grants") {
				t.Fatalf("error = %v, want duplicate-grant ambiguity", err)
			}
			if got := readPolicy(t, path); got != policyText {
				t.Errorf("ambiguous comment rewrote the policy:\n%s", got)
			}
		})
	}
}

// Neither command had an idempotence check before comments needed one; both
// always rewrote and always reported ok.
func TestHostSetAndPostureSetAreIdempotent(t *testing.T) {
	t.Parallel()
	testCases := map[string][]string{
		commandHostSet:    {"host", "set", "legacy", "100.64.0.9"},
		commandPostureSet: {"posture", "set", "posture:keep", "custom:keep == true"},
	}
	for name, command := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "acl.hujson")
			writeTestPolicy(t, path, commentAuthoringPolicy)

			stdout, err := runTailACL(t, path, command...)
			if err != nil {
				t.Fatalf("run(%q): %v", command, err)
			}
			if status := decodeStatus(t, stdout); status != statusNoChanges {
				t.Errorf("status = %q, want %q", status, statusNoChanges)
			}
			assertFixtureUnchanged(t, path)
		})
	}
}

func TestCommentAuthoringRespectsLegacyCapitalizedKeys(t *testing.T) {
	t.Parallel()
	const legacy = `{
	"TagOwners": {
		"tag:web": ["group:ops"],
	},
	"Hosts": {
		"legacy": "100.64.0.9",
	},
	"Grants": [
		{"src": ["group:keep"], "dst": ["tag:db"], "ip": ["tcp:5432"]},
	],
}
`
	testCases := []commentTarget{
		{
			commandGrantAdd,
			[]string{"grant", "add", "--src", "tag:app", "--dst", "tag:db", "--ip", "tcp:5432"},
			[]string{"Grants", "-"},
		},
		{
			commandTagOwnerAdd,
			[]string{"tag-owner", "add", "tag:web", "group:platform"},
			[]string{"TagOwners", "tag:web", "-"},
		},
		{commandHostSet, []string{"host", "set", "web", "100.64.0.10"}, []string{"Hosts", "web"}},
	}
	const comment = "Legacy spelling must survive"
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "acl.hujson")
			writeTestPolicy(t, path, legacy)

			command := append(slices.Clone(testCase.command), "--comment", comment)
			if _, err := runTailACL(t, path, command...); err != nil {
				t.Fatalf("run(%q): %v", command, err)
			}

			assertCommentsOn(t, path, []string{comment}, testCase.segments...)
			output := readPolicy(t, path)
			for _, key := range []string{"TagOwners", "Hosts", "Grants"} {
				if !strings.Contains(output, `"`+key+`"`) {
					t.Errorf("%s renamed %q:\n%s", testCase.name, key, output)
				}
				if lowered := strings.ToLower(key[:1]) + key[1:]; strings.Contains(output, `"`+lowered+`"`) {
					t.Errorf("%s added a duplicate %q key:\n%s", testCase.name, lowered, output)
				}
			}
		})
	}
}

func runTailACL(t *testing.T, path string, args ...string) (string, error) {
	t.Helper()
	var stdout strings.Builder
	err := run(
		context.Background(),
		append([]string{"--file", path, "-format", "json"}, args...),
		func(string) string { return "" },
		nil, // every command exercised here is offline.
		"",
		&stdout,
		io.Discard,
	)
	return stdout.String(), err
}

func decodeStatus(t *testing.T, stdout string) string {
	t.Helper()
	var res result
	if err := json.Unmarshal([]byte(stdout), &res); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\n%s", err, stdout)
	}
	return res.Status
}

func commentsOn(t *testing.T, path string, segments ...string) []string {
	t.Helper()
	got, err := aclpolicy.LeadingComments(path, segments...)
	if err != nil {
		t.Fatalf("LeadingComments(%v): %v", segments, err)
	}
	return got
}

func assertCommentsOn(t *testing.T, path string, want []string, segments ...string) {
	t.Helper()
	if got := commentsOn(t, path, segments...); !slices.Equal(got, want) {
		t.Errorf("comments on %v = %q, want %q\n%s", segments, got, want, readPolicy(t, path))
	}
}

func assertFixtureUnchanged(t *testing.T, path string) {
	t.Helper()
	if got := readPolicy(t, path); got != commentAuthoringPolicy {
		t.Errorf("policy was rewritten:\ngot:\n%s\nwant:\n%s", got, commentAuthoringPolicy)
	}
}

func readPolicy(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
