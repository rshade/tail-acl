package posture_test

import (
	"strings"
	"testing"

	"github.com/rshade/tsacl/pkg/policycore/posture"
)

// diagnosticCase pins one expression's diagnostics as an ordered list of
// (kind, reason fragments) pairs. Reason fragments are substrings rather than
// exact text except where a case sets exactReason, because the control
// plane's full valid-values tail is long and pinned by the guard test instead.
type diagnosticCase struct {
	name       string
	expression string
	want       []wantDiagnostic
}

type wantDiagnostic struct {
	kind        posture.DiagnosticKind
	reasonHas   []string
	exactReason string
	value       string
}

func runDiagnosticCases(t *testing.T, cases []diagnosticCase) {
	t.Helper()

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			got := posture.Validate(testCase.expression)
			if len(got) != len(testCase.want) {
				t.Fatalf("Validate(%q) returned %d diagnostics %v; want %d",
					testCase.expression, len(got), got, len(testCase.want))
			}
			for index, want := range testCase.want {
				assertDiagnostic(t, got[index], want, index)
			}
		})
	}
}

func assertDiagnostic(t *testing.T, got posture.Diagnostic, want wantDiagnostic, index int) {
	t.Helper()

	if got.Kind != want.kind {
		t.Errorf("diagnostic %d kind = %v; want %v (reason %q)", index, got.Kind, want.kind, got.Reason)
	}
	if want.exactReason != "" && got.Reason != want.exactReason {
		t.Errorf("diagnostic %d reason = %q; want exactly %q", index, got.Reason, want.exactReason)
	}
	for _, fragment := range want.reasonHas {
		if !strings.Contains(got.Reason, fragment) {
			t.Errorf("diagnostic %d reason = %q; want it to contain %q", index, got.Reason, fragment)
		}
	}
	if want.value != "" && got.Value != want.value {
		t.Errorf("diagnostic %d value = %q; want %q", index, got.Value, want.value)
	}
}

// TestValidateAcceptsValidExpressions pins the shapes that must stay
// diagnostic-free. Every grammar production is represented, including the two
// write-up trap cases: XK is in the recorded country vocabulary, and an
// unknown custom: attribute is never checked.
func TestValidateAcceptsValidExpressions(t *testing.T) {
	t.Parallel()

	expressions := []string{
		`node:os == 'linux'`,
		`node:os != 'windows'`,
		`node:osVersion >= '1.8'`,
		`node:tsVersion >= "1.40.0"`,
		`node:app == 'Tailscale'`,
		`custom:approved == true`,
		`custom:score >= 5`,
		`custom:tier IN ['gold', 'silver']`,
		`custom:tier NOT IN ["bronze"]`,
		`custom:approved IS SET`,
		`custom:approved NOT SET`,
		`node:os IS SET`,
		`node:os not set`,
		`ip:country == 'US'`,
		`ip:country IN ['US', 'XK']`,
		`ip:country NOT IN ['KP', 'IR']`,
		`ip:country IS SET`,
		`custom:approved`,
		`custom:totallyMadeUp`,
		`node:unlistedAttribute`,
		`ip:unlistedAttribute`,
	}
	for _, expression := range expressions {
		t.Run(expression, func(t *testing.T) {
			t.Parallel()

			if got := posture.Validate(expression); len(got) != 0 {
				t.Errorf("Validate(%q) = %v; want no diagnostics", expression, got)
			}
		})
	}
}

// TestValidateUnparseable pins the grammar failures. The reasons mirror the
// control plane's wording, captured from live probes on 2026-10-02.
func TestValidateUnparseable(t *testing.T) {
	t.Parallel()

	runDiagnosticCases(t, []diagnosticCase{
		{
			name:       "the write-up probe is an operator error like the server reports",
			expression: "this is not an expression",
			want: []wantDiagnostic{{
				kind: posture.DiagnosticUnparseable,
				exactReason: `expected an operator, found: "is not an", ` +
					"valid operators are: !=, <, <=, ==, >, >=, in, is set, not in, not set",
			}},
		},
		{
			name:       "operator with no literal",
			expression: "node:os ==",
			want: []wantDiagnostic{{
				kind:      posture.DiagnosticUnparseable,
				reasonHas: []string{"expected a quoted string, number, or boolean literal"},
			}},
		},
		{
			name:       "membership without a list",
			expression: "ip:country IN 'US'",
			want: []wantDiagnostic{{
				kind:      posture.DiagnosticUnparseable,
				reasonHas: []string{"expected a bracketed list of literals"},
			}},
		},
		{
			name:       "unsupported operator lists the valid operators",
			expression: `node:os =~ 'linux'`,
			want: []wantDiagnostic{{
				kind:      posture.DiagnosticUnparseable,
				reasonHas: []string{"expected an operator", "valid operators are:", "is set", "not set"},
			}},
		},
		{
			name:       "attribute outside the three namespaces",
			expression: `foo:bar == 'x'`,
			want: []wantDiagnostic{{
				kind:      posture.DiagnosticUnparseable,
				reasonHas: []string{`unsupported attribute "foo:bar"`, "node:, custom:, or ip:"},
			}},
		},
		{
			name:       "is set with an operand",
			expression: "custom:approved IS SET true",
			want: []wantDiagnostic{{
				kind:      posture.DiagnosticUnparseable,
				reasonHas: []string{"expected an operator", "valid operators are:"},
			}},
		},
		{
			name:       "empty expression",
			expression: "",
			want: []wantDiagnostic{{
				kind:      posture.DiagnosticUnparseable,
				reasonHas: []string{"empty posture expression"},
			}},
		},
	})
}

// TestValidateBareForm pins the bare truthy form's one rejectable case. The
// exact reason is the control plane's verbatim message for
// `posture set posture:bare "node:os"`, captured live on 2026-10-02: the
// server reads the bare form as an implicit comparison to true.
func TestValidateBareForm(t *testing.T) {
	t.Parallel()

	runDiagnosticCases(t, []diagnosticCase{
		{
			name:       "bare known string attribute mirrors the server message",
			expression: "node:os",
			want: []wantDiagnostic{{
				kind: posture.DiagnosticUnparseable,
				exactReason: `built-in attribute "node:os" can only be compared to string, ` +
					"got bool: true",
			}},
		},
		{
			name:       "bare known version attribute names its own type",
			expression: "node:tsVersion",
			want: []wantDiagnostic{{
				kind: posture.DiagnosticUnparseable,
				exactReason: `built-in attribute "node:tsVersion" can only be compared to version, ` +
					"got bool: true",
			}},
		},
	})
}

// TestValidateUnknownAttribute pins the warning-level kind: node: and ip:
// attributes the editorial table does not list. The reason mirrors the
// control plane's "does not exist" wording, but the kind is warning-level
// because the table goes stale as the server grows attributes.
func TestValidateUnknownAttribute(t *testing.T) {
	t.Parallel()

	runDiagnosticCases(t, []diagnosticCase{
		{
			name:       "the write-up probe",
			expression: "node:bogusattr == 'x'",
			want: []wantDiagnostic{{
				kind:        posture.DiagnosticUnknownAttribute,
				exactReason: `attribute "node:bogusattr" does not exist`,
			}},
		},
		{
			name:       "unknown ip attribute",
			expression: "ip:city == 'Berlin'",
			want: []wantDiagnostic{{
				kind:        posture.DiagnosticUnknownAttribute,
				exactReason: `attribute "ip:city" does not exist`,
			}},
		},
	})
}

// TestValidateUnknownCountry pins the ip:country vocabulary check against the
// recorded server list. The reason mirrors the control plane's "unexpected
// value" wording, including the list index for membership expressions.
func TestValidateUnknownCountry(t *testing.T) {
	t.Parallel()

	runDiagnosticCases(t, []diagnosticCase{
		{
			// The server's own probe flagged only "AB" at index 0: CD is a
			// valid code (it is in the recorded list), which is exactly why a
			// hand-maintained ISO table is not good enough here.
			name:       "the write-up probe flags only the genuinely bad code",
			expression: "ip:country NOT IN ['AB', 'CD']",
			want: []wantDiagnostic{
				{
					kind:      posture.DiagnosticUnknownValue,
					value:     "AB",
					reasonHas: []string{`list value at index 0: unexpected value "AB"`, "valid values: AD, AE"},
				},
			},
		},
		{
			name:       "two bad codes are both flagged in order",
			expression: "ip:country NOT IN ['AB', 'XY']",
			want: []wantDiagnostic{
				{
					kind:      posture.DiagnosticUnknownValue,
					value:     "AB",
					reasonHas: []string{`list value at index 0: unexpected value "AB"`, "valid values: AD, AE"},
				},
				{
					kind:      posture.DiagnosticUnknownValue,
					value:     "XY",
					reasonHas: []string{`list value at index 1: unexpected value "XY"`, "valid values:"},
				},
			},
		},
		{
			name:       "a scalar bad code has no list index",
			expression: "ip:country == 'AB'",
			want: []wantDiagnostic{{
				kind:      posture.DiagnosticUnknownValue,
				value:     "AB",
				reasonHas: []string{`unexpected value "AB"`, "valid values: AD, AE"},
			}},
		},
		{
			name:       "one bad code among good ones",
			expression: "ip:country IN ['US', 'ZZ', 'XK']",
			want: []wantDiagnostic{{
				kind:      posture.DiagnosticUnknownValue,
				value:     "ZZ",
				reasonHas: []string{`list value at index 1: unexpected value "ZZ"`},
			}},
		},
	})
}

// TestDiagnosticKindLevels pins which kinds block: every kind except
// DiagnosticUnknownAttribute is error-level. tsacl's lint mapping and
// posture set's accept/warn decision both rest on this.
func TestDiagnosticKindLevels(t *testing.T) {
	t.Parallel()

	tests := []struct {
		kind       posture.DiagnosticKind
		name       string
		errorLevel bool
	}{
		{posture.DiagnosticUnparseable, "unparseable", true},
		{posture.DiagnosticUnknownAttribute, "unknown-attribute", false},
		{posture.DiagnosticUnknownValue, "unknown-value", true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			if got := test.kind.ErrorLevel(); got != test.errorLevel {
				t.Errorf("%v.ErrorLevel() = %v; want %v", test.kind, got, test.errorLevel)
			}
			if got := test.kind.String(); got != test.name {
				t.Errorf("%v.String() = %q; want %q", test.kind, got, test.name)
			}
		})
	}
}
