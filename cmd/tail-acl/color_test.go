package main

import (
	"context"
	"encoding/json"
	"io"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/rshade/tail-acl/internal/aclpolicy"
)

// colorEnabled encodes the machine contract: JSON never colors, --color=never is
// off, --color=always is on, and auto depends on NO_COLOR plus a real TTY. The
// writer here is a [strings.Builder], which is never a terminal, so auto is off
// even when NO_COLOR is unset — the property every test that renders into a
// buffer relies on to stay ASCII-clean.
func TestColorEnabled(t *testing.T) {
	t.Parallel()
	noEnv := func(string) string { return "" }
	withNoColor := func(string) string { return "1" }
	var buf strings.Builder
	cases := []struct {
		name   string
		format string
		mode   colorMode
		getenv func(string) string
		want   bool
	}{
		{"json always still off", formatJSON, colorAlways, noEnv, false},
		{"json auto off", formatJSON, colorAuto, noEnv, false},
		{"human never off", formatHuman, colorNever, noEnv, false},
		{"human always on", formatHuman, colorAlways, noEnv, true},
		{"human always beats NO_COLOR", formatHuman, colorAlways, withNoColor, true},
		{"human auto non-tty off", formatHuman, colorAuto, noEnv, false},
		{"human auto NO_COLOR off", formatHuman, colorAuto, withNoColor, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := colorEnabled(tc.format, tc.mode, &buf, tc.getenv); got != tc.want {
				t.Errorf("colorEnabled(%q, %v) = %v, want %v", tc.format, tc.mode, got, tc.want)
			}
		})
	}
}

// TestColorAllowedByEnv covers the half of the auto decision a test can reach.
// colorEnabled's other half, isTerminalWriter, is false for every writer a test
// can supply, so asserting an env signal through colorEnabled would pass no
// matter what the policy did.
func TestColorAllowedByEnv(t *testing.T) {
	t.Parallel()
	env := func(pairs map[string]string) func(string) string {
		return func(key string) string { return pairs[key] }
	}
	for _, testCase := range []struct {
		name string
		vars map[string]string
		want bool
	}{
		{name: "clean environment allows color", vars: nil, want: true},
		{name: "NO_COLOR disables", vars: map[string]string{"NO_COLOR": "1"}, want: false},
		{name: "TERM=dumb disables", vars: map[string]string{"TERM": termDumb}, want: false},
		{name: "an ordinary TERM allows", vars: map[string]string{"TERM": "xterm-256color"}, want: true},
		{
			name: "TERM=dumb disables even with a normal NO_COLOR",
			vars: map[string]string{"TERM": termDumb, "NO_COLOR": ""},
			want: false,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			if got := colorAllowedByEnv(env(testCase.vars)); got != testCase.want {
				t.Errorf("colorAllowedByEnv(%v) = %v, want %v", testCase.vars, got, testCase.want)
			}
		})
	}
}

func TestParseColorMode(t *testing.T) {
	t.Parallel()
	cases := map[string]struct {
		want colorMode
		ok   bool
	}{
		"auto":   {colorAuto, true},
		"always": {colorAlways, true},
		"never":  {colorNever, true},
		"":       {colorAuto, false},
		"yes":    {colorAuto, false},
		"Auto":   {colorAuto, false},
	}
	for raw, want := range cases {
		t.Run(raw, func(t *testing.T) {
			t.Parallel()
			got, ok := parseColorMode(raw)
			if got != want.want || ok != want.ok {
				t.Errorf("parseColorMode(%q) = %v, %v; want %v, %v", raw, got, ok, want.want, want.ok)
			}
		})
	}
}

// severityColor is the single mapping both the per-finding prefix and the
// summary counts route through; a drift here would desync the two.
func TestSeverityColor(t *testing.T) {
	t.Parallel()
	cases := map[aclpolicy.LintSeverity]string{
		aclpolicy.LintError:  ansiRed,
		aclpolicy.LintWarn:   ansiYellow,
		aclpolicy.LintInfo:   ansiBlue,
		aclpolicy.LintAdvice: ansiDim,
	}
	for severity, want := range cases {
		if got := severityColor(severity); got != want {
			t.Errorf("severityColor(%q) = %q, want %q", severity, got, want)
		}
	}
}

// countColor renders green for the all-clear zero and the severity's own color
// for any nonzero tally.
func TestCountColor(t *testing.T) {
	t.Parallel()
	if got := countColor(aclpolicy.LintError, 0); got != ansiGreen {
		t.Errorf("countColor(error, 0) = %q, want green %q", got, ansiGreen)
	}
	if got := countColor(aclpolicy.LintError, 3); got != ansiRed {
		t.Errorf("countColor(error, 3) = %q, want red %q", got, ansiRed)
	}
	if got := countColor(aclpolicy.LintWarn, 0); got != ansiGreen {
		t.Errorf("countColor(warn, 0) = %q, want green %q", got, ansiGreen)
	}
}

// paint is the choke point that makes enabled=false a guaranteed identity, which
// is what keeps a no-color run byte-for-byte identical and ASCII-clean.
func TestPaintDisabledIsIdentity(t *testing.T) {
	t.Parallel()
	if got := paint(false, ansiRed, "ERROR"); got != "ERROR" {
		t.Errorf("paint(false, ...) = %q, want unchanged", got)
	}
	if got := paint(true, ansiRed, "ERROR"); got != ansiRed+"ERROR"+ansiReset {
		t.Errorf("paint(true, ...) = %q, want wrapped", got)
	}
	if got := paint(true, "", "ERROR"); got != "ERROR" {
		t.Errorf("paint(true, empty code, ...) = %q, want unchanged", got)
	}
}

// mixedSeverityPolicy yields "2 findings: 0 error, 0 warn, 1 info, 1 advice":
// an INFO (unused group) and an ADVICE (untested broad rule), plus a zero error
// and zero warn count for the green all-clear assertion.
const mixedSeverityPolicy = `{
	"groups": {
		"group:dev": ["alice@example.com"],
		"group:unused": ["nobody@example.com"]
	},
	"tagOwners": {"tag:db": ["group:dev"]},
	"grants": [
		{"src": ["autogroup:member"], "dst": ["tag:db"], "ip": ["*"]},
		{"src": ["group:dev"], "dst": ["tag:db"], "ip": ["tcp:5432"]}
	]
}`

// With --color=always the human summary and the per-finding prefixes carry ANSI,
// even though stdout here is a buffer (not a TTY) — always is the override that
// forces color for pipes and pagers, and doubles as the test hook.
//
// -severity advice is explicit here because it makes every displayed finding
// fatal, so this test covers both the full set of severity colors and exit 1.
// The omitted flag would display the same findings but retain warn as its
// failure floor and exit 0 for this policy.
func TestLintColorAlwaysPaintsSeverities(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.hujson")
	writeTestPolicy(t, path, mixedSeverityPolicy)
	var stdout, stderr strings.Builder
	err := run(
		context.Background(),
		[]string{"--file", path, "--color", "always", cmdLint, "--severity", "advice"},
		func(string) string { return "" },
		nil,
		"",
		&stdout,
		&stderr,
	)
	if code := exitCode(err); code != exitFailed {
		t.Fatalf("exit code = %d, want %d (error %v)", code, exitFailed, err)
	}
	out := stdout.String()
	for _, want := range []string{
		// INFO prefix in blue, ADVICE prefix dimmed.
		ansiBlue + "INFO" + ansiReset + " unused-group",
		ansiDim + "ADVICE" + ansiReset + " broad-rule-untested",
		// Zero error/warn render green (all-clear); the info tally is blue.
		"tail-acl: 2 findings: " + ansiGreen + "0 error" + ansiReset,
		ansiGreen + "0 warn" + ansiReset,
		ansiBlue + "1 info" + ansiReset,
		ansiDim + "1 advice" + ansiReset,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("stdout missing colored span %q:\n%q", want, out)
		}
	}
}

// JSON is the machine contract: --color=always must not leak a single escape
// into the envelope, and the envelope must still parse.
func TestLintColorAlwaysLeavesJSONClean(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.hujson")
	writeTestPolicy(t, path, mixedSeverityPolicy)
	var stdout, stderr strings.Builder
	err := run(
		context.Background(),
		[]string{"--file", path, "--format", "json", "--color", "always", cmdLint},
		func(string) string { return "" },
		nil,
		"",
		&stdout,
		&stderr,
	)
	if code := exitCode(err); code != exitOK {
		t.Fatalf("exit code = %d, want %d (error %v)", code, exitOK, err)
	}
	out := stdout.String()
	if strings.Contains(out, "\x1b") {
		t.Errorf("JSON envelope contains ANSI escape:\n%q", out)
	}
	var envelope result
	if unmarshalErr := json.Unmarshal([]byte(out), &envelope); unmarshalErr != nil {
		t.Errorf("JSON does not parse: %v\n%q", unmarshalErr, out)
	}
}

// An unknown --color value is a usage error (exit 2), the same class as an
// unknown --format.
// TestLintColorIsPurelyDecorative pins the contract the coloured renderer
// exists to honour: stripping the escapes must yield exactly the uncoloured
// output, byte for byte, in every branch of the summary line.
//
// It is asserted here rather than left to the plain-path tests because those
// cannot see the coloured writer at all. Two mutations to renderLintSummaryLine
// otherwise pass the entire suite: dropping its trailing newline, so a TTY lint
// runs into the shell prompt; and skipping the uncoloured segments when the
// threshold withheld findings, so a terminal user loses the "N at or above
// warn" lead-in and the "-severity advice shows/fails on all" hint that the
// JSON message still carries.
func TestLintColorIsPurelyDecorative(t *testing.T) {
	t.Parallel()
	escape := regexp.MustCompile(`\x1b\[[0-9;]*m`)
	for _, testCase := range []struct {
		name   string
		policy string
		args   []string
	}{
		{
			name:   "clean policy",
			policy: `{"tagOwners": {"tag:web": ["autogroup:admin"]}, "grants": []}`,
		},
		{
			name:   "explicit threshold withholds everything",
			policy: mixedLintPolicy,
			args:   []string{"-severity", "warn"},
		},
		{
			name:   "threshold withholds nothing",
			policy: mixedLintPolicy,
			args:   []string{"-severity", "advice"},
		},
		{
			name:   "explicit threshold withholds some",
			policy: `{"grants": [{"src": ["*"], "dst": ["*"], "ip": ["tcp:443"]}, {"src": ["group:x@corp.example"], "dst": ["tag:nobody"], "ip": ["tcp:80"]}]}`,
			args:   []string{"-severity", "warn"},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "acl.hujson")
			writeTestPolicy(t, path, testCase.policy)

			lint := func(mode string) string {
				var stdout strings.Builder
				args := append([]string{"--color", mode, "--file", path, cmdLint}, testCase.args...)
				_ = run(
					context.Background(), args,
					func(string) string { return "" }, nil, "", &stdout, io.Discard,
				)
				return stdout.String()
			}
			painted, plain := lint("always"), lint("never")
			if stripped := escape.ReplaceAllString(painted, ""); stripped != plain {
				t.Errorf("stripping color changed the output:\n painted: %q\nstripped: %q\n   plain: %q",
					painted, stripped, plain)
			}
			if painted == plain {
				t.Errorf("--color always produced no escapes at all:\n%q", painted)
			}
		})
	}
}

func TestLintColorRejectsUnknownMode(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.hujson")
	writeTestPolicy(t, path, mixedSeverityPolicy)
	var stdout, stderr strings.Builder
	err := run(
		context.Background(),
		[]string{"--file", path, "--color", "rainbow", cmdLint},
		func(string) string { return "" },
		nil,
		"",
		&stdout,
		&stderr,
	)
	if code := exitCode(err); code != exitUsage {
		t.Fatalf("exit code = %d, want %d (error %v)", code, exitUsage, err)
	}
}
