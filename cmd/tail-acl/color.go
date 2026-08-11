package main

import (
	"io"
	"os"

	"golang.org/x/term"

	"github.com/rshade/tailscale-utils/tail-acl/internal/aclpolicy"
)

// colorMode is the resolved value of --color. auto is the default: color only
// when stdout is a real terminal, human format is selected, and NO_COLOR is
// unset. always and never are explicit overrides for pipes, pagers, and CI.
type colorMode int

const (
	colorAuto colorMode = iota
	colorAlways
	colorNever
)

// The --color flag's three accepted values, named once so the parser and the
// default in run() cannot drift.
const (
	colorModeAuto   = "auto"
	colorModeAlways = "always"
	colorModeNever  = "never"
)

// parseColorMode maps the --color flag string to a colorMode. The bool is false
// for an unknown value so the caller can raise a usage error rather than
// silently defaulting.
func parseColorMode(raw string) (colorMode, bool) {
	switch raw {
	case colorModeAuto:
		return colorAuto, true
	case colorModeAlways:
		return colorAlways, true
	case colorModeNever:
		return colorNever, true
	default:
		return colorAuto, false
	}
}

// ANSI SGR codes. Basic 16-color only, chosen for legibility on a dark
// background: bright blue (94) reads better than plain blue (34) for INFO, and
// dim (2) recedes ADVICE without a hue that competes with the real severities.
const (
	ansiReset  = "\x1b[0m"
	ansiRed    = "\x1b[31m"
	ansiGreen  = "\x1b[32m"
	ansiYellow = "\x1b[33m"
	ansiBlue   = "\x1b[94m"
	ansiDim    = "\x1b[2m"
)

// severityColor is the single severity->color mapping. Both the per-finding
// prefix (renderLintFinding) and the summary counts (lintSummarySegments) route
// through it, so the two can never disagree about what red means.
func severityColor(severity aclpolicy.LintSeverity) string {
	switch severity {
	case aclpolicy.LintError:
		return ansiRed
	case aclpolicy.LintWarn:
		return ansiYellow
	case aclpolicy.LintInfo:
		return ansiBlue
	case aclpolicy.LintAdvice:
		return ansiDim
	default:
		return ""
	}
}

// countColor colors a summary count: green when the count is zero (an all-clear
// signal that "0 error" is a good thing), otherwise the severity's own color.
func countColor(severity aclpolicy.LintSeverity, n int) string {
	if n == 0 {
		return ansiGreen
	}
	return severityColor(severity)
}

// paint wraps s in the SGR code and a reset when enabled, and returns s
// untouched otherwise. All colorization routes through this, so enabled=false is
// a guaranteed no-op — the plain path stays byte-identical and ASCII-clean. An
// empty code (unknown severity) also passes through unwrapped.
func paint(enabled bool, code, s string) string {
	if !enabled || code == "" {
		return s
	}
	return code + s + ansiReset
}

// isTerminalWriter reports whether w is a real terminal. run() is handed an
// [io.Writer] (tests pass a [strings.Builder], which is never a TTY), so
// detection happens here by type-asserting to the concrete [os.File] rather
// than adding a TTY flag to every call site.
func isTerminalWriter(w io.Writer) bool {
	f, ok := w.(*os.File)
	return ok && term.IsTerminal(int(f.Fd()))
}

// termDumb is the TERM value that means the terminal cannot render SGR.
const termDumb = "dumb"

// colorAllowedByEnv reports whether the environment permits color under the
// auto mode. It is split from colorEnabled so the env policy is testable
// without a pty: isTerminalWriter is false for every writer a test can hand
// colorEnabled, which would make an env case pass whatever the policy said.
//
// TERM=dumb is the standard "this terminal cannot render SGR" signal - Emacs
// shell-mode, some CI pty runners, serial consoles - and it *is* a terminal, so
// IsTerminal alone says yes and the escapes arrive as literal garbage.
// --color always still overrides both signals, exactly as it does for NO_COLOR.
func colorAllowedByEnv(getenv func(string) string) bool {
	return getenv("TERM") != termDumb && getenv("NO_COLOR") == ""
}

// colorEnabled resolves whether to emit ANSI on w. The machine contract wins
// over everything: JSON is never colored regardless of --color, so a consumer
// piping -format json --color=always still gets a clean envelope.
//
// NO_COLOR: the injected getenv cannot distinguish an unset variable from one
// set to the empty string, so this uses the common "any non-empty value
// disables" interpretation rather than the spec's stricter "presence disables".
// --color=always overrides NO_COLOR, matching how an explicit flag beats an env
// default elsewhere in the tool.
func colorEnabled(format string, mode colorMode, w io.Writer, getenv func(string) string) bool {
	if format == formatJSON {
		return false
	}
	switch mode {
	case colorNever:
		return false
	case colorAlways:
		return true
	case colorAuto:
		return colorAllowedByEnv(getenv) && isTerminalWriter(w)
	default:
		return false
	}
}
