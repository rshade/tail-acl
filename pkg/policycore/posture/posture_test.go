package posture_test

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rshade/tail-acl/pkg/policycore/posture"
)

const (
	// testPosture is the posture name every case passes to Evaluate. Verdict.Posture
	// must echo it back unchanged so a caller can attribute a verdict without
	// tracking the argument itself.
	testPosture = "posture:test"

	// liveClientVersion is a real Device.ClientVersion from this repo's own capture
	// (tailnet-audit/internal/audit/testdata/snapshot_devices_live.json). Every
	// version comparison must truncate the build suffix at the first "-".
	liveClientVersion = "1.98.8-t1241b225b-g0520dfda5"

	// attributesVersion is the clean version string the posture attributes endpoint
	// returns, per the upstream client's own captured response.
	attributesVersion = "1.40.0"

	// oversizedLiteralLength and deepNestingLength size the hostile inputs in
	// TestEvaluateNeverPanics.
	oversizedLiteralLength = 4096
	deepNestingLength      = 64
)

// ruleCase is one single-rule evaluation. The single-rule tables share it so
// adding an operator or a literal kind is one line rather than another loop.
type ruleCase struct {
	name  string
	rule  string
	facts posture.Facts
	want  posture.State
	// reasonHas lists substrings Verdict.Reason must contain, checked in addition
	// to the empty-exactly-when-Satisfied invariant.
	reasonHas []string
}

// testNow is the fixed capture time the tables evaluate against. It is a
// function because the repo lint config forbids package-level variables.
func testNow() time.Time {
	return time.Date(2026, time.July, 21, 12, 0, 0, 0, time.UTC)
}

// deviceFacts is a device with no collected posture attributes: only the two
// fields the devices listing carries.
func deviceFacts(deviceOS, clientVersion string) posture.Facts {
	return posture.Facts{OS: deviceOS, ClientVersion: clientVersion}
}

// collectedFacts is a device whose posture attribute fetch succeeded.
func collectedFacts(attributes map[string]any) posture.Facts {
	return posture.Facts{Attributes: attributes, Collected: true}
}

// expiringFacts is a successfully collected device whose custom:approved
// attribute is true and expires at expiry.
func expiringFacts(expiry time.Time) posture.Facts {
	return posture.Facts{
		Attributes: map[string]any{"custom:approved": true},
		Expiries:   map[string]time.Time{"custom:approved": expiry},
		Collected:  true,
	}
}

func runRuleCases(t *testing.T, cases []ruleCase) {
	t.Helper()

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			verdict := posture.Evaluate(testPosture, []string{testCase.rule}, testCase.facts, testNow())
			assertVerdict(t, verdict, testCase.want, testCase.reasonHas)
		})
	}
}

func assertVerdict(t *testing.T, verdict posture.Verdict, want posture.State, reasonHas []string) {
	t.Helper()

	if verdict.Posture != testPosture {
		t.Errorf("Verdict.Posture = %q; want %q", verdict.Posture, testPosture)
	}
	if verdict.State != want {
		t.Errorf("Verdict.State = %v; want %v (Reason %q)", verdict.State, want, verdict.Reason)
	}
	switch {
	case want == posture.Satisfied && verdict.Reason != "":
		t.Errorf("Verdict.Reason = %q; want empty when the posture is satisfied", verdict.Reason)
	case want != posture.Satisfied && verdict.Reason == "":
		t.Errorf("Verdict.Reason is empty; want it to name the fact that decided %v", want)
	}
	for _, fragment := range reasonHas {
		if !strings.Contains(verdict.Reason, fragment) {
			t.Errorf("Verdict.Reason = %q; want it to contain %q", verdict.Reason, fragment)
		}
	}
}

// TestStateZeroValueIsUnknown pins the iota order. Unknown must be the zero
// value so a Verdict nobody filled in reads as unevaluable rather than as a
// pass or a failure.
func TestStateZeroValueIsUnknown(t *testing.T) {
	t.Parallel()

	var zero posture.State
	if zero != posture.Unknown {
		t.Errorf("zero State = %v; want Unknown", zero)
	}
}

func TestStateString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		state posture.State
		want  string
	}{
		{state: posture.Unknown, want: "unknown"},
		{state: posture.Satisfied, want: "satisfied"},
		{state: posture.Unsatisfied, want: "unsatisfied"},
	}
	for _, testCase := range tests {
		t.Run(testCase.want, func(t *testing.T) {
			t.Parallel()

			if got := testCase.state.String(); got != testCase.want {
				t.Errorf("State.String() = %q; want %q", got, testCase.want)
			}
		})
	}
}

// TestStateMarshalText pins the machine contract: the three state names are what
// reaches a JSON consumer, so encoding a State must go through MarshalText and
// never leak the underlying integer.
func TestStateMarshalText(t *testing.T) {
	t.Parallel()

	tests := []struct {
		state posture.State
		want  string
	}{
		{state: posture.Unknown, want: "unknown"},
		{state: posture.Satisfied, want: "satisfied"},
		{state: posture.Unsatisfied, want: "unsatisfied"},
	}
	for _, testCase := range tests {
		t.Run(testCase.want, func(t *testing.T) {
			t.Parallel()

			text, err := testCase.state.MarshalText()
			if err != nil {
				t.Fatalf("State.MarshalText() error = %v", err)
			}
			if string(text) != testCase.want {
				t.Errorf("State.MarshalText() = %q; want %q", text, testCase.want)
			}

			encoded, err := json.Marshal(testCase.state)
			if err != nil {
				t.Fatalf("json.Marshal(State) error = %v", err)
			}
			if quoted := `"` + testCase.want + `"`; string(encoded) != quoted {
				t.Errorf("json.Marshal(State) = %s; want %s", encoded, quoted)
			}
		})
	}
}

// TestEvaluateEqualityOperators covers "==" and "!=" against every literal kind
// the grammar admits: double-quoted, single-quoted, number, and bool.
func TestEvaluateEqualityOperators(t *testing.T) {
	t.Parallel()

	// 5.0 rather than 5 because JSON numbers decode to float64, which is what the
	// collector stores in Facts.Attributes.
	facts := collectedFacts(map[string]any{
		"custom:tier":     "gold",
		"custom:score":    5.0,
		"custom:approved": true,
	})

	runRuleCases(t, []ruleCase{
		{name: "double quoted match", rule: `custom:tier == "gold"`, facts: facts, want: posture.Satisfied},
		{
			name:      "double quoted mismatch",
			rule:      `custom:tier == "silver"`,
			facts:     facts,
			want:      posture.Unsatisfied,
			reasonHas: []string{`custom:tier == "silver"`},
		},
		{name: "single quoted match", rule: `custom:tier == 'gold'`, facts: facts, want: posture.Satisfied},
		{
			name:      "single quoted mismatch",
			rule:      `custom:tier == 'silver'`,
			facts:     facts,
			want:      posture.Unsatisfied,
			reasonHas: []string{`custom:tier == 'silver'`},
		},
		{name: "number match", rule: "custom:score == 5", facts: facts, want: posture.Satisfied},
		{
			name:      "number mismatch",
			rule:      "custom:score == 6",
			facts:     facts,
			want:      posture.Unsatisfied,
			reasonHas: []string{"custom:score == 6"},
		},
		{name: "bool match", rule: "custom:approved == true", facts: facts, want: posture.Satisfied},
		{
			name:      "bool mismatch",
			rule:      "custom:approved == false",
			facts:     facts,
			want:      posture.Unsatisfied,
			reasonHas: []string{"custom:approved == false"},
		},
		{name: "inequality double quoted", rule: `custom:tier != "silver"`, facts: facts, want: posture.Satisfied},
		{
			name:      "inequality double quoted against the actual value",
			rule:      `custom:tier != "gold"`,
			facts:     facts,
			want:      posture.Unsatisfied,
			reasonHas: []string{`custom:tier != "gold"`},
		},
		{name: "inequality single quoted", rule: `custom:tier != 'silver'`, facts: facts, want: posture.Satisfied},
		{name: "inequality number", rule: "custom:score != 6", facts: facts, want: posture.Satisfied},
		{
			name:      "inequality number against the actual value",
			rule:      "custom:score != 5",
			facts:     facts,
			want:      posture.Unsatisfied,
			reasonHas: []string{"custom:score != 5"},
		},
		{name: "inequality bool", rule: "custom:approved != false", facts: facts, want: posture.Satisfied},
		{
			name:      "inequality bool against the actual value",
			rule:      "custom:approved != true",
			facts:     facts,
			want:      posture.Unsatisfied,
			reasonHas: []string{"custom:approved != true"},
		},
		{
			name:  "integer valued attribute compares numerically",
			rule:  "custom:count == 3",
			facts: collectedFacts(map[string]any{"custom:count": 3}),
			want:  posture.Satisfied,
		},
		{
			name:  "fractional literal",
			rule:  "custom:ratio == 1.5",
			facts: collectedFacts(map[string]any{"custom:ratio": 1.5}),
			want:  posture.Satisfied,
		},
		{
			name:  "extra whitespace around the operator",
			rule:  `custom:tier   ==   "gold"`,
			facts: facts,
			want:  posture.Satisfied,
		},
		{name: "surrounding whitespace", rule: `  custom:tier == "gold"  `, facts: facts, want: posture.Satisfied},
	})
}

// TestEvaluateOrderedOperators covers "<", "<=", ">", and ">=". Numbers and
// node:tsVersion are the only values the plan gives an ordering (D-A4), so an
// ordered comparison against anything else is Unknown rather than a guess --
// the same discipline D-A4 already applies to a version field that does not
// parse as an integer.
func TestEvaluateOrderedOperators(t *testing.T) {
	t.Parallel()

	numeric := collectedFacts(map[string]any{"custom:score": 7.0})
	live := deviceFacts("", liveClientVersion)

	runRuleCases(t, []ruleCase{
		{name: "greater than", rule: "custom:score > 5", facts: numeric, want: posture.Satisfied},
		{
			name:      "greater than at the boundary",
			rule:      "custom:score > 7",
			facts:     numeric,
			want:      posture.Unsatisfied,
			reasonHas: []string{"custom:score > 7"},
		},
		{name: "greater or equal at the boundary", rule: "custom:score >= 7", facts: numeric, want: posture.Satisfied},
		{
			name:      "greater or equal above the value",
			rule:      "custom:score >= 8",
			facts:     numeric,
			want:      posture.Unsatisfied,
			reasonHas: []string{"custom:score >= 8"},
		},
		{name: "less than", rule: "custom:score < 9", facts: numeric, want: posture.Satisfied},
		{
			name:      "less than at the boundary",
			rule:      "custom:score < 7",
			facts:     numeric,
			want:      posture.Unsatisfied,
			reasonHas: []string{"custom:score < 7"},
		},
		{name: "less or equal at the boundary", rule: "custom:score <= 7", facts: numeric, want: posture.Satisfied},
		{
			name:      "less or equal below the value",
			rule:      "custom:score <= 6",
			facts:     numeric,
			want:      posture.Unsatisfied,
			reasonHas: []string{"custom:score <= 6"},
		},
		{name: "fractional literal", rule: "custom:score >= 6.5", facts: numeric, want: posture.Satisfied},
		{
			name:  "integer valued attribute",
			rule:  "custom:count <= 3",
			facts: collectedFacts(map[string]any{"custom:count": 3}),
			want:  posture.Satisfied,
		},
		{name: "double quoted version literal", rule: `node:tsVersion >= "1.40"`, facts: live, want: posture.Satisfied},
		{name: "single quoted version literal", rule: `node:tsVersion >= '1.40'`, facts: live, want: posture.Satisfied},
		{
			name:      "bool has no ordering",
			rule:      "custom:approved >= true",
			facts:     collectedFacts(map[string]any{"custom:approved": true}),
			want:      posture.Unknown,
			reasonHas: []string{"custom:approved"},
		},
		{
			name:      "a plain string has no ordering",
			rule:      `custom:tier < "gold"`,
			facts:     collectedFacts(map[string]any{"custom:tier": "silver"}),
			want:      posture.Unknown,
			reasonHas: []string{"custom:tier"},
		},
	})
}

// TestEvaluateMembershipOperators covers "IN" and "NOT IN" against every
// literal kind, and pins the keyword as case-insensitive per the grammar.
func TestEvaluateMembershipOperators(t *testing.T) {
	t.Parallel()

	facts := collectedFacts(map[string]any{
		"custom:tier":     "gold",
		"custom:score":    5.0,
		"custom:approved": true,
	})

	runRuleCases(t, []ruleCase{
		{
			name:  "double quoted list member",
			rule:  `custom:tier IN ["gold", "silver"]`,
			facts: facts,
			want:  posture.Satisfied,
		},
		{
			name:      "double quoted list non member",
			rule:      `custom:tier IN ["silver", "bronze"]`,
			facts:     facts,
			want:      posture.Unsatisfied,
			reasonHas: []string{`custom:tier IN ["silver", "bronze"]`},
		},
		{name: "single quoted list member", rule: `custom:tier IN ['gold']`, facts: facts, want: posture.Satisfied},
		{
			name:      "single quoted list non member",
			rule:      `custom:tier IN ['silver']`,
			facts:     facts,
			want:      posture.Unsatisfied,
			reasonHas: []string{`custom:tier IN ['silver']`},
		},
		{name: "number list member", rule: "custom:score IN [1, 5, 9]", facts: facts, want: posture.Satisfied},
		{
			name:      "number list non member",
			rule:      "custom:score IN [1, 9]",
			facts:     facts,
			want:      posture.Unsatisfied,
			reasonHas: []string{"custom:score IN [1, 9]"},
		},
		{name: "bool list member", rule: "custom:approved IN [true]", facts: facts, want: posture.Satisfied},
		{
			name:      "bool list non member",
			rule:      "custom:approved IN [false]",
			facts:     facts,
			want:      posture.Unsatisfied,
			reasonHas: []string{"custom:approved IN [false]"},
		},
		{name: "single element list", rule: `custom:tier IN ["gold"]`, facts: facts, want: posture.Satisfied},
		{name: "lowercase in keyword", rule: `custom:tier in ["gold"]`, facts: facts, want: posture.Satisfied},
		{name: "mixed case in keyword", rule: `custom:tier In ["gold"]`, facts: facts, want: posture.Satisfied},
		{
			name:  "list whitespace is tolerated",
			rule:  `custom:tier IN [  "silver" ,  "gold"  ]`,
			facts: facts,
			want:  posture.Satisfied,
		},
		{
			name:  "not in a list it is absent from",
			rule:  `custom:tier NOT IN ["silver"]`,
			facts: facts,
			want:  posture.Satisfied,
		},
		{
			name:      "not in a list it is present in",
			rule:      `custom:tier NOT IN ["gold", "silver"]`,
			facts:     facts,
			want:      posture.Unsatisfied,
			reasonHas: []string{`custom:tier NOT IN ["gold", "silver"]`},
		},
		{
			name:  "lowercase not in keyword",
			rule:  `custom:tier not in ["silver"]`,
			facts: facts,
			want:  posture.Satisfied,
		},
		{
			name:  "mixed case not in keyword",
			rule:  `custom:tier Not In ["silver"]`,
			facts: facts,
			want:  posture.Satisfied,
		},
		{name: "not in a number list", rule: "custom:score NOT IN [1, 9]", facts: facts, want: posture.Satisfied},
		{
			name:      "not in a number list it is present in",
			rule:      "custom:score NOT IN [1, 5]",
			facts:     facts,
			want:      posture.Unsatisfied,
			reasonHas: []string{"custom:score NOT IN [1, 5]"},
		},
		{name: "not in a bool list", rule: "custom:approved NOT IN [false]", facts: facts, want: posture.Satisfied},
	})
}

// TestEvaluateBareAttribute covers the bare-truthy form, which takes no literal.
func TestEvaluateBareAttribute(t *testing.T) {
	t.Parallel()

	runRuleCases(t, []ruleCase{
		{
			name:  "true is satisfied",
			rule:  "custom:approved",
			facts: collectedFacts(map[string]any{"custom:approved": true}),
			want:  posture.Satisfied,
		},
		{
			name:      "false is unsatisfied",
			rule:      "custom:approved",
			facts:     collectedFacts(map[string]any{"custom:approved": false}),
			want:      posture.Unsatisfied,
			reasonHas: []string{"custom:approved"},
		},
		{
			name:  "surrounding whitespace is tolerated",
			rule:  "  custom:approved  ",
			facts: collectedFacts(map[string]any{"custom:approved": true}),
			want:  posture.Satisfied,
		},
		{
			name:  "node namespace bare form",
			rule:  "node:tsAutoUpdate",
			facts: collectedFacts(map[string]any{"node:tsAutoUpdate": true}),
			want:  posture.Satisfied,
		},
	})
}

// TestEvaluateNodeOSIsCaseInsensitive proves node:os normalizes both sides, in
// both directions: the API makes no documented case guarantee, and a silent
// false Unsatisfied on a "macOS" vs "macos" mismatch would be a wrong verdict
// rather than an honest Unknown.
func TestEvaluateNodeOSIsCaseInsensitive(t *testing.T) {
	t.Parallel()

	runRuleCases(t, []ruleCase{
		{
			name:  "uppercase device os against a lowercase literal",
			rule:  `node:os == "linux"`,
			facts: deviceFacts("Linux", ""),
			want:  posture.Satisfied,
		},
		{
			name:  "lowercase device os against an uppercase literal",
			rule:  `node:os IN ["Linux"]`,
			facts: deviceFacts("linux", ""),
			want:  posture.Satisfied,
		},
		{
			name:  "mixed case device os",
			rule:  `node:os == "macos"`,
			facts: deviceFacts("macOS", ""),
			want:  posture.Satisfied,
		},
		{
			name:  "mixed case literal in a list",
			rule:  `node:os IN ["macOS", "windows"]`,
			facts: deviceFacts("macos", ""),
			want:  posture.Satisfied,
		},
		{
			name:      "inequality normalizes both sides",
			rule:      `node:os != "Windows"`,
			facts:     deviceFacts("windows", ""),
			want:      posture.Unsatisfied,
			reasonHas: []string{`node:os != "Windows"`},
		},
		{
			name:      "not in normalizes both sides",
			rule:      `node:os NOT IN ["LINUX"]`,
			facts:     deviceFacts("linux", ""),
			want:      posture.Unsatisfied,
			reasonHas: []string{`node:os NOT IN ["LINUX"]`},
		},
		{
			name:      "a different os is unsatisfied",
			rule:      `node:os == "windows"`,
			facts:     deviceFacts("linux", ""),
			want:      posture.Unsatisfied,
			reasonHas: []string{`node:os == "windows"`},
		},
	})
}

// TestEvaluateDeviceFieldsResolveWithoutCollectedAttributes proves node:os and
// node:tsVersion come from the devices listing, so the two most common gates
// stay evaluable with -posture-attributes off. Without this, the default
// invocation could evaluate nothing at all.
func TestEvaluateDeviceFieldsResolveWithoutCollectedAttributes(t *testing.T) {
	t.Parallel()

	facts := deviceFacts("linux", liveClientVersion)

	runRuleCases(t, []ruleCase{
		{name: "node os", rule: `node:os == "linux"`, facts: facts, want: posture.Satisfied},
		{name: "node ts version", rule: `node:tsVersion >= "1.40"`, facts: facts, want: posture.Satisfied},
		{name: "node os membership", rule: `node:os IN ["linux", "windows"]`, facts: facts, want: posture.Satisfied},
	})
}

// TestEvaluateNodeVersion pins version handling: the build suffix is truncated
// at the first "-", ordered operators compare dot-separated integer fields with
// missing fields as zero, and equality-style operators compare the truncated
// string. A field that does not parse as an integer is Unknown and names the
// value it could not read.
func TestEvaluateNodeVersion(t *testing.T) {
	t.Parallel()

	live := deviceFacts("", liveClientVersion)

	runRuleCases(t, []ruleCase{
		{
			name:  "build suffix is truncated before an ordered comparison",
			rule:  `node:tsVersion >= "1.40"`,
			facts: live,
			want:  posture.Satisfied,
		},
		{
			name:      "ordered comparison against a newer version",
			rule:      `node:tsVersion >= "2.0"`,
			facts:     live,
			want:      posture.Unsatisfied,
			reasonHas: []string{`node:tsVersion >= "2.0"`},
		},
		{
			name:  "equality compares the truncated string",
			rule:  `node:tsVersion == "1.98.8"`,
			facts: live,
			want:  posture.Satisfied,
		},
		{
			name:      "equality against the untruncated string",
			rule:      `node:tsVersion == "` + liveClientVersion + `"`,
			facts:     live,
			want:      posture.Unsatisfied,
			reasonHas: []string{liveClientVersion},
		},
		{
			name:      "inequality compares the truncated string",
			rule:      `node:tsVersion != "1.98.8"`,
			facts:     live,
			want:      posture.Unsatisfied,
			reasonHas: []string{`node:tsVersion != "1.98.8"`},
		},
		{
			name:  "membership compares the truncated string",
			rule:  `node:tsVersion IN ["1.98.8"]`,
			facts: live,
			want:  posture.Satisfied,
		},
		{
			name:  "missing fields count as zero on the fact side",
			rule:  `node:tsVersion >= "1.40.0"`,
			facts: deviceFacts("", "1.40"),
			want:  posture.Satisfied,
		},
		{
			name:  "missing fields count as zero on the literal side",
			rule:  `node:tsVersion >= "1.40"`,
			facts: deviceFacts("", "1.40.0"),
			want:  posture.Satisfied,
		},
		{
			name:      "missing fields do not make a version greater",
			rule:      `node:tsVersion > "1.40.0"`,
			facts:     deviceFacts("", "1.40"),
			want:      posture.Unsatisfied,
			reasonHas: []string{`node:tsVersion > "1.40.0"`},
		},
		{
			name:  "fields compare as integers not lexicographically",
			rule:  `node:tsVersion >= "1.9"`,
			facts: deviceFacts("", "1.10.0"),
			want:  posture.Satisfied,
		},
		{
			name:      "unparseable fact version",
			rule:      `node:tsVersion >= "1.40"`,
			facts:     deviceFacts("", "unstable"),
			want:      posture.Unknown,
			reasonHas: []string{"unstable"},
		},
		{
			name:      "unparseable literal version",
			rule:      `node:tsVersion >= "latest"`,
			facts:     live,
			want:      posture.Unknown,
			reasonHas: []string{"latest"},
		},
		{
			name:      "empty client version",
			rule:      `node:tsVersion >= "1.40"`,
			facts:     deviceFacts("", ""),
			want:      posture.Unknown,
			reasonHas: []string{"node:tsVersion"},
		},
	})
}

// TestEvaluateAttributePrecedence pins the resolution order of D-A4: a
// successfully collected attribute is the control plane's own posture input, so
// it wins over the device field; the device field is only the fallback. Facts
// values are already lowercase here so the ordering is tested independently of
// node:os case normalization.
func TestEvaluateAttributePrecedence(t *testing.T) {
	t.Parallel()

	runRuleCases(t, []ruleCase{
		{
			name: "collected version wins over the device field",
			rule: `node:tsVersion == "` + attributesVersion + `"`,
			facts: posture.Facts{
				OS:            "linux",
				ClientVersion: liveClientVersion,
				Attributes:    map[string]any{"node:tsVersion": attributesVersion},
				Collected:     true,
			},
			want: posture.Satisfied,
		},
		{
			name: "collected os wins over the device field",
			rule: `node:os == "windows"`,
			facts: posture.Facts{
				OS:         "linux",
				Attributes: map[string]any{"node:os": "windows"},
				Collected:  true,
			},
			want: posture.Satisfied,
		},
		{
			name: "device os is the fallback when the key is absent",
			rule: `node:os == "linux"`,
			facts: posture.Facts{
				OS:         "linux",
				Attributes: map[string]any{"custom:tier": "gold"},
				Collected:  true,
			},
			want: posture.Satisfied,
		},
		{
			name: "device version is the fallback when the key is absent",
			rule: `node:tsVersion >= "1.40"`,
			facts: posture.Facts{
				ClientVersion: liveClientVersion,
				Attributes:    map[string]any{"custom:tier": "gold"},
				Collected:     true,
			},
			want: posture.Satisfied,
		},
		{
			name:      "a populated attribute map is ignored when collection was not requested",
			rule:      `custom:tier == "gold"`,
			facts:     posture.Facts{Attributes: map[string]any{"custom:tier": "gold"}},
			want:      posture.Unknown,
			reasonHas: []string{"custom:tier", "-posture-attributes"},
		},
	})
}

// TestEvaluateUnsetAttribute pins D-A5. A custom attribute absent from a
// successful collection really is unset, so a positive comparison against it
// fails. A negated comparison against it is Unknown: claiming an unset
// attribute satisfies a negation would be a guess about Tailscale's semantics.
func TestEvaluateUnsetAttribute(t *testing.T) {
	t.Parallel()

	present := collectedFacts(map[string]any{"custom:other": true})
	nilMap := collectedFacts(nil)

	runRuleCases(t, []ruleCase{
		{
			name:      "equality is unsatisfied",
			rule:      "custom:approved == true",
			facts:     present,
			want:      posture.Unsatisfied,
			reasonHas: []string{"custom:approved", "not set"},
		},
		{
			name:      "membership is unsatisfied",
			rule:      `custom:tier IN ["gold"]`,
			facts:     present,
			want:      posture.Unsatisfied,
			reasonHas: []string{"custom:tier", "not set"},
		},
		{
			name:      "ordered comparison is unsatisfied",
			rule:      "custom:score >= 5",
			facts:     present,
			want:      posture.Unsatisfied,
			reasonHas: []string{"custom:score", "not set"},
		},
		{
			name:      "bare form is unsatisfied",
			rule:      "custom:approved",
			facts:     present,
			want:      posture.Unsatisfied,
			reasonHas: []string{"custom:approved", "not set"},
		},
		{
			name:      "a nil attribute map behaves as unset",
			rule:      "custom:approved == true",
			facts:     nilMap,
			want:      posture.Unsatisfied,
			reasonHas: []string{"custom:approved", "not set"},
		},
		{
			name:      "inequality is unknown",
			rule:      "custom:approved != true",
			facts:     present,
			want:      posture.Unknown,
			reasonHas: []string{"custom:approved", "not set"},
		},
		{
			name:      "not in is unknown",
			rule:      `custom:tier NOT IN ["gold"]`,
			facts:     present,
			want:      posture.Unknown,
			reasonHas: []string{"custom:tier", "not set"},
		},
		{
			name:  "not set is satisfied",
			rule:  "custom:approved NOT SET",
			facts: present,
			want:  posture.Satisfied,
		},
		{
			name:      "is set is unsatisfied",
			rule:      "custom:approved IS SET",
			facts:     present,
			want:      posture.Unsatisfied,
			reasonHas: []string{"custom:approved", "not set"},
		},
		{
			name:  "lowercase not set is satisfied",
			rule:  "custom:approved not set",
			facts: present,
			want:  posture.Satisfied,
		},
	})
}

// TestEvaluateSetOperators pins the IS SET / NOT SET operators against the
// resolution tri-state: IS SET is Satisfied exactly when the attribute
// resolves, Unsatisfied when it is genuinely unset, and Unknown when the
// capture cannot say; NOT SET is the mirror. NOT SET is the only operator an
// absent attribute satisfies — it asks the question "is this unset?" directly.
func TestEvaluateSetOperators(t *testing.T) {
	t.Parallel()

	present := collectedFacts(map[string]any{"custom:approved": true, "custom:zero": 0.0})
	empty := collectedFacts(nil)

	runRuleCases(t, []ruleCase{
		{
			name:  "is set on a resolved attribute",
			rule:  "custom:approved IS SET",
			facts: present,
			want:  posture.Satisfied,
		},
		{
			name:  "is set on a resolved zero value",
			rule:  "custom:zero IS SET",
			facts: present,
			want:  posture.Satisfied,
		},
		{
			name:      "not set on a resolved attribute",
			rule:      "custom:approved NOT SET",
			facts:     present,
			want:      posture.Unsatisfied,
			reasonHas: []string{"custom:approved NOT SET"},
		},
		{
			name:      "is set on an absent attribute",
			rule:      "custom:missing IS SET",
			facts:     empty,
			want:      posture.Unsatisfied,
			reasonHas: []string{"custom:missing", "not set"},
		},
		{
			name:  "not set on an absent attribute",
			rule:  "custom:missing NOT SET",
			facts: empty,
			want:  posture.Satisfied,
		},
		{
			name:  "is set on a device-field attribute",
			rule:  "node:os IS SET",
			facts: deviceFacts("linux", ""),
			want:  posture.Satisfied,
		},
		{
			name:      "is set on an attribute the capture cannot carry",
			rule:      "node:tsReleaseTrack IS SET",
			facts:     present,
			want:      posture.Unknown,
			reasonHas: []string{"node:tsReleaseTrack", "not carried"},
		},
		{
			name:      "not set on an attribute the capture cannot carry",
			rule:      "node:tsReleaseTrack NOT SET",
			facts:     present,
			want:      posture.Unknown,
			reasonHas: []string{"node:tsReleaseTrack", "not carried"},
		},
		{
			name:      "is set on an uncollected attribute",
			rule:      "custom:approved IS SET",
			facts:     deviceFacts("linux", ""),
			want:      posture.Unknown,
			reasonHas: []string{"custom:approved", "-posture-attributes"},
		},
		{
			name:  "lowercase is set",
			rule:  "custom:approved is set",
			facts: present,
			want:  posture.Satisfied,
		},
		{
			name:  "mixed case is set",
			rule:  "custom:approved Is Set",
			facts: present,
			want:  posture.Satisfied,
		},
		{
			name:  "mixed case not set",
			rule:  "custom:missing Not Set",
			facts: empty,
			want:  posture.Satisfied,
		},
		{
			name:      "an expired attribute is unset for is set",
			rule:      "custom:approved IS SET",
			facts:     expiringFacts(testNow().Add(-time.Hour)),
			want:      posture.Unsatisfied,
			reasonHas: []string{"custom:approved", "expired"},
		},
		{
			name:  "an expired attribute is unset for not set",
			rule:  "custom:approved NOT SET",
			facts: expiringFacts(testNow().Add(-time.Hour)),
			want:  posture.Satisfied,
		},
	})
}

// TestEvaluateIPNamespace pins the ip: attribute namespace. The devices
// listing carries no GeoIP fact, so an ip: attribute the posture capture does
// not carry is Unknown — missing data, never an unset attribute the device
// could be failed for.
func TestEvaluateIPNamespace(t *testing.T) {
	t.Parallel()

	carried := collectedFacts(map[string]any{"ip:country": "US"})

	runRuleCases(t, []ruleCase{
		{
			name:  "equality on a carried country",
			rule:  `ip:country == 'US'`,
			facts: carried,
			want:  posture.Satisfied,
		},
		{
			name:  "membership on a carried country",
			rule:  `ip:country IN ['US', 'CA']`,
			facts: carried,
			want:  posture.Satisfied,
		},
		{
			name:  "is set on a carried country",
			rule:  "ip:country IS SET",
			facts: carried,
			want:  posture.Satisfied,
		},
		{
			name:      "equality on a country the capture does not carry",
			rule:      `ip:country == 'US'`,
			facts:     collectedFacts(nil),
			want:      posture.Unknown,
			reasonHas: []string{"ip:country", "not carried"},
		},
		{
			name:      "not set on a country the capture does not carry",
			rule:      "ip:country NOT SET",
			facts:     collectedFacts(nil),
			want:      posture.Unknown,
			reasonHas: []string{"ip:country", "not carried"},
		},
	})
}

// TestEvaluateExpiredAttribute pins expiry handling. An expiry that is non-zero
// and not after now makes the attribute behave exactly as unset, and the reason
// names the expiry rendered as [time.RFC3339] -- the format the JSON envelope
// already uses for every other timestamp. A zero now cannot decide an expiry at
// all, so the verdict is Unknown rather than a guess in either direction; that
// mirrors the zero-CapturedAt discipline in the key-expiry check.
func TestEvaluateExpiredAttribute(t *testing.T) {
	t.Parallel()

	expiry := time.Date(2026, time.July, 20, 9, 30, 0, 0, time.UTC)
	expiryText := expiry.Format(time.RFC3339)

	tests := []struct {
		name      string
		rule      string
		facts     posture.Facts
		now       time.Time
		want      posture.State
		reasonHas []string
	}{
		{
			name:      "expired before the capture",
			rule:      "custom:approved == true",
			facts:     expiringFacts(expiry),
			now:       testNow(),
			want:      posture.Unsatisfied,
			reasonHas: []string{"custom:approved", expiryText},
		},
		{
			name:      "an expiry exactly at the capture time has passed",
			rule:      "custom:approved == true",
			facts:     expiringFacts(expiry),
			now:       expiry,
			want:      posture.Unsatisfied,
			reasonHas: []string{"custom:approved", expiryText},
		},
		{
			name:  "an expiry after the capture time is live",
			rule:  "custom:approved == true",
			facts: expiringFacts(expiry),
			now:   expiry.Add(-time.Second),
			want:  posture.Satisfied,
		},
		{
			name:  "a zero expiry means no expiry",
			rule:  "custom:approved == true",
			facts: expiringFacts(time.Time{}),
			now:   testNow(),
			want:  posture.Satisfied,
		},
		{
			name:      "an expired attribute makes a negation unknown",
			rule:      "custom:approved != false",
			facts:     expiringFacts(expiry),
			now:       testNow(),
			want:      posture.Unknown,
			reasonHas: []string{"custom:approved"},
		},
		{
			name:      "a zero capture time cannot decide an expiry",
			rule:      "custom:approved == true",
			facts:     expiringFacts(expiry),
			now:       time.Time{},
			want:      posture.Unknown,
			reasonHas: []string{"custom:approved"},
		},
		{
			name:  "a zero capture time does not poison an attribute with no expiry",
			rule:  "custom:approved == true",
			facts: collectedFacts(map[string]any{"custom:approved": true}),
			now:   time.Time{},
			want:  posture.Satisfied,
		},
		{
			name: "another attribute's expiry is not applied",
			rule: "custom:approved == true",
			facts: posture.Facts{
				Attributes: map[string]any{"custom:approved": true},
				Expiries:   map[string]time.Time{"custom:other": expiry},
				Collected:  true,
			},
			now:  testNow(),
			want: posture.Satisfied,
		},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			verdict := posture.Evaluate(testPosture, []string{testCase.rule}, testCase.facts, testCase.now)
			assertVerdict(t, verdict, testCase.want, testCase.reasonHas)
		})
	}
}

// TestEvaluateWithoutCollectedAttributes proves an attribute that needs the
// opt-in fan-out is Unknown and says so by naming the flag. This is the honest
// alternative to a silent Pass on a gate nothing evaluated.
func TestEvaluateWithoutCollectedAttributes(t *testing.T) {
	t.Parallel()

	facts := deviceFacts("linux", liveClientVersion)

	runRuleCases(t, []ruleCase{
		{
			name:      "custom attribute",
			rule:      "custom:deviceApproved == true",
			facts:     facts,
			want:      posture.Unknown,
			reasonHas: []string{"custom:deviceApproved", "-posture-attributes"},
		},
		{
			name:      "node attribute the devices listing does not carry",
			rule:      `node:tsReleaseTrack == "stable"`,
			facts:     facts,
			want:      posture.Unknown,
			reasonHas: []string{"node:tsReleaseTrack", "-posture-attributes"},
		},
		{
			name:      "bare custom attribute",
			rule:      "custom:deviceApproved",
			facts:     facts,
			want:      posture.Unknown,
			reasonHas: []string{"custom:deviceApproved", "-posture-attributes"},
		},
		{
			name:      "negated custom attribute",
			rule:      "custom:deviceApproved != true",
			facts:     facts,
			want:      posture.Unknown,
			reasonHas: []string{"custom:deviceApproved", "-posture-attributes"},
		},
		{
			name:      "custom attribute membership",
			rule:      `custom:tier IN ["gold"]`,
			facts:     facts,
			want:      posture.Unknown,
			reasonHas: []string{"custom:tier", "-posture-attributes"},
		},
	})
}

// TestEvaluateWithFailedAttributeFetch proves a device whose attribute fetch
// failed reports uncertainty carrying that device's error, and that it does not
// lose the two facts the devices listing already supplied: node:os and
// node:tsVersion stay definite, so one failed fetch does not erase every
// verdict for that device.
func TestEvaluateWithFailedAttributeFetch(t *testing.T) {
	t.Parallel()

	const fetchError = "attributes request failed with status 403"

	facts := posture.Facts{
		OS:            "linux",
		ClientVersion: liveClientVersion,
		Collected:     true,
		CollectError:  fetchError,
	}

	runRuleCases(t, []ruleCase{
		{
			name:      "custom attribute is unknown",
			rule:      "custom:deviceApproved == true",
			facts:     facts,
			want:      posture.Unknown,
			reasonHas: []string{fetchError},
		},
		{
			name:      "negated custom attribute is unknown",
			rule:      "custom:deviceApproved != true",
			facts:     facts,
			want:      posture.Unknown,
			reasonHas: []string{fetchError},
		},
		{
			name:      "bare custom attribute is unknown",
			rule:      "custom:deviceApproved",
			facts:     facts,
			want:      posture.Unknown,
			reasonHas: []string{fetchError},
		},
		{name: "node os stays definite", rule: `node:os == "linux"`, facts: facts, want: posture.Satisfied},
		{name: "node version stays definite", rule: `node:tsVersion >= "1.40"`, facts: facts, want: posture.Satisfied},
	})
}

// TestEvaluateNodeAttributeAbsentFromCollectedAttributes pins the distinction
// D-A4 draws against TestEvaluateUnsetAttribute: a node: attribute is an
// intrinsic device fact, so a capture that does not carry it is missing data
// (Unknown, naming the devices listing), while an absent custom: attribute
// really is unset (Unsatisfied). Only node:os and node:tsVersion have a
// devices-listing fallback.
func TestEvaluateNodeAttributeAbsentFromCollectedAttributes(t *testing.T) {
	t.Parallel()

	facts := collectedFacts(map[string]any{"custom:tier": "gold"})

	runRuleCases(t, []ruleCase{
		{
			name:      "release track",
			rule:      `node:tsReleaseTrack == "stable"`,
			facts:     facts,
			want:      posture.Unknown,
			reasonHas: []string{"node:tsReleaseTrack", "devices listing"},
		},
		{
			name:      "os version",
			rule:      `node:osVersion == "5.19.0-42-generic"`,
			facts:     facts,
			want:      posture.Unknown,
			reasonHas: []string{"node:osVersion", "devices listing"},
		},
		{
			name:      "auto update bare form",
			rule:      "node:tsAutoUpdate",
			facts:     facts,
			want:      posture.Unknown,
			reasonHas: []string{"node:tsAutoUpdate", "devices listing"},
		},
	})
}

// TestEvaluateKleeneComposition pins the three-valued AND. Unsatisfied
// dominates Unknown deliberately: it is the only composition that lets a
// definite failure survive alongside an unevaluable sibling rule, so the check
// still finds real gaps on a tailnet whose postures mix evaluable and
// unevaluable attributes. The Unknown rule here is an unsupported expression,
// which is Unknown for a reason independent of attribute resolution.
func TestEvaluateKleeneComposition(t *testing.T) {
	t.Parallel()

	facts := collectedFacts(map[string]any{"custom:tier": "silver", "custom:approved": true})

	const (
		satisfiedRule   = "custom:approved == true"
		unsatisfiedRule = `custom:tier == "gold"`
		unknownRule     = "this is not a posture expression"
	)

	tests := []struct {
		name      string
		rules     []string
		want      posture.State
		reasonHas []string
	}{
		{
			name:      "unsatisfied dominates unknown",
			rules:     []string{unsatisfiedRule, unknownRule},
			want:      posture.Unsatisfied,
			reasonHas: []string{unsatisfiedRule},
		},
		{
			name:      "unsatisfied dominates unknown in either order",
			rules:     []string{unknownRule, unsatisfiedRule},
			want:      posture.Unsatisfied,
			reasonHas: []string{unsatisfiedRule},
		},
		{
			name:      "unknown survives alongside satisfied",
			rules:     []string{satisfiedRule, unknownRule},
			want:      posture.Unknown,
			reasonHas: []string{unknownRule},
		},
		{
			name:      "unknown survives alongside satisfied in either order",
			rules:     []string{unknownRule, satisfiedRule},
			want:      posture.Unknown,
			reasonHas: []string{unknownRule},
		},
		{
			name:  "every rule satisfied",
			rules: []string{satisfiedRule, `custom:tier == "silver"`},
			want:  posture.Satisfied,
		},
		{
			name:      "unsatisfied dominates satisfied",
			rules:     []string{satisfiedRule, unsatisfiedRule},
			want:      posture.Unsatisfied,
			reasonHas: []string{unsatisfiedRule},
		},
		{
			name:      "unsatisfied dominates a mix of all three",
			rules:     []string{satisfiedRule, unknownRule, unsatisfiedRule},
			want:      posture.Unsatisfied,
			reasonHas: []string{unsatisfiedRule},
		},
		{
			name:      "every rule unknown",
			rules:     []string{unknownRule, unknownRule},
			want:      posture.Unknown,
			reasonHas: []string{unknownRule},
		},
		{
			name:      "a single unsatisfied rule",
			rules:     []string{unsatisfiedRule},
			want:      posture.Unsatisfied,
			reasonHas: []string{unsatisfiedRule},
		},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			verdict := posture.Evaluate(testPosture, testCase.rules, facts, testNow())
			assertVerdict(t, verdict, testCase.want, testCase.reasonHas)
		})
	}
}

// TestEvaluateUnsupportedExpressions proves anything outside the grammar is
// Unknown and quotes the expression back, so a grammar gap is self-documenting
// rather than a wrong verdict.
func TestEvaluateUnsupportedExpressions(t *testing.T) {
	t.Parallel()

	facts := collectedFacts(map[string]any{"custom:tier": "gold", "node:os": "linux"})

	tests := []struct {
		name string
		rule string
		// quotesRule is false only for a blank expression, where asserting the
		// reason contains it would be vacuous.
		quotesRule bool
	}{
		{name: "operator with no literal", rule: "node:os ==", quotesRule: true},
		{name: "membership with no attribute", rule: "IN [1,2]", quotesRule: true},
		{name: "empty expression", rule: ""},
		{name: "whitespace only expression", rule: "   "},
		{name: "unterminated list", rule: "node:os IN [1,2", quotesRule: true},
		{name: "attribute with no namespace", rule: `noprefix == "x"`, quotesRule: true},
		{name: "unrecognized namespace", rule: `posture:other == "x"`, quotesRule: true},
		{name: "empty attribute name", rule: `node: == "x"`, quotesRule: true},
		{name: "unsupported operator", rule: `node:os =~ "linux"`, quotesRule: true},
		{name: "triple equals", rule: `node:os === "linux"`, quotesRule: true},
		{name: "membership without a list", rule: `node:os IN "linux"`, quotesRule: true},
		{name: "empty list", rule: "node:os IN []", quotesRule: true},
		{name: "unquoted string literal", rule: "node:os == linux", quotesRule: true},
		{name: "trailing garbage after the literal", rule: `node:os == "linux" extra`, quotesRule: true},
		{name: "conjunction", rule: `node:os == "linux" && custom:tier == "gold"`, quotesRule: true},
		{name: "operator with no attribute", rule: `== "linux"`, quotesRule: true},
		{name: "list with a trailing comma", rule: `node:os IN ["linux",]`, quotesRule: true},
		{name: "unterminated string literal", rule: `custom:tier == "gold`, quotesRule: true},
		{name: "mismatched quotes", rule: `custom:tier == "gold'`, quotesRule: true},
		{name: "is set with an operand", rule: "custom:tier IS SET true", quotesRule: true},
		{name: "not set with an operand", rule: `custom:tier NOT SET ['a']`, quotesRule: true},
		{name: "not without a keyword", rule: `custom:tier NOT ['a']`, quotesRule: true},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			reasonHas := []string{"unsupported posture expression"}
			if testCase.quotesRule {
				reasonHas = append(reasonHas, testCase.rule)
			}
			verdict := posture.Evaluate(testPosture, []string{testCase.rule}, facts, testNow())
			assertVerdict(t, verdict, posture.Unknown, reasonHas)
		})
	}
}

// TestEvaluateNeverPanics feeds the evaluator hostile and malformed input. A
// posture expression arrives verbatim from a customer's policy document, so a
// panic here would take down an audit run over data the operator does not
// control. Every input must land on one of the three states with the Reason
// invariant intact; which state is deliberately not pinned here.
func TestEvaluateNeverPanics(t *testing.T) {
	t.Parallel()

	facts := posture.Facts{
		OS:            "linux",
		ClientVersion: liveClientVersion,
		Attributes: map[string]any{
			"custom:tier":   "gold",
			"custom:nested": map[string]any{"inner": "value"},
			"custom:list":   []any{"a", "b"},
			"custom:null":   nil,
		},
		Expiries:  map[string]time.Time{"custom:tier": testNow().Add(time.Hour)},
		Collected: true,
	}

	tests := []struct {
		name string
		rule string
	}{
		{name: "empty", rule: ""},
		{name: "single space", rule: " "},
		{name: "tabs and newlines", rule: "\t\n"},
		{name: "open bracket", rule: "["},
		{name: "close bracket", rule: "]"},
		{name: "empty brackets", rule: "[]"},
		{name: "bare equality operator", rule: "=="},
		{name: "bare inequality operator", rule: "!="},
		{name: "bare less than", rule: "<"},
		{name: "bare in keyword", rule: "IN"},
		{name: "bare not in keyword", rule: "NOT IN"},
		{name: "bare is set keyword", rule: "IS SET"},
		{name: "bare not set keyword", rule: "NOT SET"},
		{name: "bare not keyword", rule: "custom:tier NOT"},
		{name: "bare is keyword", rule: "custom:tier IS"},
		{name: "unterminated double quote", rule: `custom:tier == "`},
		{name: "unterminated single quote", rule: `custom:tier == '`},
		{name: "unterminated list open", rule: "custom:tier IN ["},
		{name: "reversed list bracket", rule: "custom:tier IN ]"},
		{name: "nested lists", rule: `custom:tier IN [["a"],["b"]]`},
		{name: "map valued attribute", rule: `custom:nested == "inner"`},
		{name: "slice valued attribute", rule: `custom:list IN ["a"]`},
		{name: "null valued attribute equality", rule: `custom:null == "x"`},
		{name: "null valued attribute bare", rule: "custom:null"},
		{name: "null valued attribute negation", rule: `custom:null != "x"`},
		{name: "string valued attribute bare", rule: "custom:tier"},
		{name: "empty literal", rule: `node:os == ""`},
		{name: "non ascii literal", rule: `node:os == "линукс"`},
		{name: "non ascii attribute name", rule: `custom:téléphone == true`},
		{name: "two operators", rule: "custom:tier < >= 1"},
		{name: "chained comparison", rule: `custom:tier == "a" == "b"`},
		{name: "version with empty fields", rule: `node:tsVersion >= ".."`},
		{name: "version with a negative field", rule: `node:tsVersion >= "1.-1"`},
		{name: "membership with no list", rule: "custom:tier NOT IN"},
		{name: "bare node os", rule: "node:os"},
		{name: "bare node version", rule: "node:tsVersion"},
		{name: "oversized literal", rule: `custom:tier == "` + strings.Repeat("x", oversizedLiteralLength) + `"`},
		{name: "deeply nested brackets", rule: strings.Repeat("[", deepNestingLength)},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			verdict := posture.Evaluate(testPosture, []string{testCase.rule}, facts, testNow())
			if verdict.Posture != testPosture {
				t.Errorf("Verdict.Posture = %q; want %q", verdict.Posture, testPosture)
			}
			switch verdict.State {
			case posture.Satisfied:
				if verdict.Reason != "" {
					t.Errorf("Verdict.Reason = %q; want empty when the posture is satisfied", verdict.Reason)
				}
			case posture.Unsatisfied, posture.Unknown:
				if verdict.Reason == "" {
					t.Errorf("Verdict.Reason is empty for state %v", verdict.State)
				}
			}
		})
	}
}

// TestEvaluateEmptyRuleList pins the empty conjunction. Rules are ANDed, so a
// posture whose rule list is empty constrains nothing and is vacuously
// Satisfied. A posture the policy never defines is a different case and never
// reaches Evaluate: per D-A5 the check reports an undefined posture as Unknown
// before it has any rules to evaluate.
func TestEvaluateEmptyRuleList(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		rules []string
	}{
		{name: "nil rules"},
		{name: "empty rules", rules: []string{}},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			verdict := posture.Evaluate(testPosture, testCase.rules, posture.Facts{}, testNow())
			assertVerdict(t, verdict, posture.Satisfied, nil)
		})
	}
}

// TestEvaluateEchoesPostureName proves Verdict.Posture is the name argument
// verbatim, whatever it is. The check keys one finding per (device, posture)
// pair off this field, so a rewritten or dropped name would mis-attribute the
// finding.
func TestEvaluateEchoesPostureName(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		given string
	}{
		{name: "conventional posture name", given: "posture:latestMac"},
		{name: "empty name", given: ""},
		{name: "unprefixed name", given: "not-a-posture"},
		{name: "name with spaces", given: "posture:with spaces"},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			rules := []string{`node:os == "linux"`}
			verdict := posture.Evaluate(testCase.given, rules, deviceFacts("linux", ""), testNow())
			if verdict.Posture != testCase.given {
				t.Errorf("Verdict.Posture = %q; want %q", verdict.Posture, testCase.given)
			}
			if verdict.State != posture.Satisfied {
				t.Errorf("Verdict.State = %v; want Satisfied", verdict.State)
			}
		})
	}
}

func TestReferencedAttributes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		rules []string
		want  []string
	}{
		{name: "nil rules"},
		{name: "empty rules", rules: []string{}},
		{
			name: "sorted and deduped across operators",
			rules: []string{
				`custom:tier == "gold"`,
				"custom:approved",
				`custom:tier != "silver"`,
				`node:os IN ["linux"]`,
				"custom:score >= 5",
			},
			want: []string{"custom:approved", "custom:score", "custom:tier", "node:os"},
		},
		{
			name:  "single rule",
			rules: []string{`node:tsVersion >= "1.40"`},
			want:  []string{"node:tsVersion"},
		},
		{
			name:  "a repeated attribute appears once",
			rules: []string{"custom:approved", "custom:approved", "custom:approved == true"},
			want:  []string{"custom:approved"},
		},
		{
			name:  "both namespaces sort together",
			rules: []string{`node:os == "linux"`, "custom:zeta", "custom:alpha", "node:tsAutoUpdate"},
			want:  []string{"custom:alpha", "custom:zeta", "node:os", "node:tsAutoUpdate"},
		},
		{
			name:  "surrounding whitespace is trimmed",
			rules: []string{`   custom:tier == "gold"   `},
			want:  []string{"custom:tier"},
		},
		{
			name:  "input order does not matter",
			rules: []string{"custom:zeta", `node:os == "linux"`, "custom:alpha"},
			want:  []string{"custom:alpha", "custom:zeta", "node:os"},
		},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			got := posture.ReferencedAttributes(testCase.rules)
			if len(testCase.want) == 0 {
				if len(got) != 0 {
					t.Errorf("ReferencedAttributes(%q) = %v; want no attributes", testCase.rules, got)
				}
				return
			}
			if !slices.Equal(got, testCase.want) {
				t.Errorf("ReferencedAttributes(%q) = %v; want %v", testCase.rules, got, testCase.want)
			}
		})
	}
}

// TestReferencedAttributesToleratesUnparsableRules proves a malformed rule
// neither panics nor breaks the sorted-and-distinct contract, and that the
// well-formed rule beside it is still reported. Whether a malformed rule
// contributes its leading token is deliberately not pinned: the plan does not
// specify it, and the check only needs a conservative superset.
func TestReferencedAttributesToleratesUnparsableRules(t *testing.T) {
	t.Parallel()

	got := posture.ReferencedAttributes([]string{
		"",
		"   ",
		"node:os ==",
		"IN [1,2]",
		`noprefix == "x"`,
		"custom:tier IN [1,2",
		`custom:tier == "gold"`,
	})

	if !slices.IsSorted(got) {
		t.Errorf("ReferencedAttributes = %v; want sorted", got)
	}
	if compacted := slices.Compact(slices.Clone(got)); len(compacted) != len(got) {
		t.Errorf("ReferencedAttributes = %v; want distinct entries", got)
	}
	if !slices.Contains(got, "custom:tier") {
		t.Errorf("ReferencedAttributes = %v; want custom:tier from the one well-formed rule", got)
	}
	for _, attribute := range got {
		if !strings.HasPrefix(attribute, "node:") && !strings.HasPrefix(attribute, "custom:") {
			t.Errorf("ReferencedAttributes returned %q; want only node: or custom: attribute names", attribute)
		}
	}
}
