package posture_test

import (
	"strings"
	"testing"

	"github.com/rshade/tail-acl/pkg/policycore/posture"
)

// attrsCase pins one posture's verdict against one attribute set.
type attrsCase struct {
	name string
	// posture is the posture name; rules are its expressions.
	posture string
	rules   []string
	attrs   posture.Attrs
	want    posture.State
	// decidingHas lists substrings the deciding rule's Reason must contain.
	// A satisfied posture has no deciding rule, so it pins the satisfied
	// rules' reasons instead via satisfiedHas.
	decidingHas  []string
	satisfiedHas []string
}

func runAttrsCases(t *testing.T, cases []attrsCase) {
	t.Helper()

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			outcome := posture.EvaluatePosture(testCase.posture, testCase.rules, testCase.attrs)
			if outcome.Posture != testCase.posture {
				t.Errorf("Outcome.Posture = %q; want %q", outcome.Posture, testCase.posture)
			}
			if got := outcome.State(); got != testCase.want {
				t.Errorf("State() = %v; want %v (rules %#v)", got, testCase.want, outcome.Rules)
			}
			if len(outcome.Rules) != len(testCase.rules) {
				t.Fatalf("Rules = %#v; want one verdict per expression", outcome.Rules)
			}
			assertAttrsReasons(t, outcome, testCase)
		})
	}
}

func assertAttrsReasons(t *testing.T, outcome posture.Outcome, testCase attrsCase) {
	t.Helper()

	deciding, decided := outcome.DecidingRule()
	if testCase.want == posture.Satisfied {
		if decided {
			t.Errorf("DecidingRule() = %#v; want none for a satisfied posture", deciding)
		}
		for index, fragment := range testCase.satisfiedHas {
			if index < len(outcome.Rules) && !strings.Contains(outcome.Rules[index].Reason, fragment) {
				t.Errorf("Rules[%d].Reason = %q; want it to contain %q",
					index, outcome.Rules[index].Reason, fragment)
			}
		}
		return
	}
	if !decided {
		t.Fatal("DecidingRule() found no deciding rule for a non-satisfied posture")
	}
	for _, fragment := range testCase.decidingHas {
		if !strings.Contains(deciding.Reason, fragment) {
			t.Errorf("deciding Reason = %q; want it to contain %q", deciding.Reason, fragment)
		}
	}
}

// complete wraps a map with the completeness assertion srcPostureAttrs
// carries: what the map omits is unset.
func complete(attrs map[string]any) posture.Attrs {
	return posture.Attrs{Map: attrs, Complete: true}
}

// partial wraps a map without the completeness assertion: what the map omits
// is unknown, not unset.
func partial(attrs map[string]any) posture.Attrs {
	return posture.Attrs{Map: attrs}
}

// TestEvaluatePostureReferenceTruthTable reproduces every verdict of the
// reference policy's truth table (Features write-up 04), whose seven tests
// were confirmed passing on the control plane (example.ts.net) on
// 2026-10-02. The four postures and grants below are that policy's; each
// case is one (test, grant) pair and the state is whether that grant's
// posture gate opens for the test's srcPostureAttrs.
func TestEvaluatePostureReferenceTruthTable(t *testing.T) {
	t.Parallel()

	const (
		steeringNotSet    = "posture:steering-not-set"
		steeringNotSetGeo = "posture:steering-not-set-geo-unset"
		nyc               = "posture:nyc"
		nycGeoUnset       = "posture:nyc-geo-unset"
	)
	rules := map[string][]string{
		steeringNotSet:    {"custom:subnet_router NOT SET", "ip:country NOT IN ['KP', 'IR']"},
		steeringNotSetGeo: {"custom:subnet_router NOT SET", "ip:country NOT SET"},
		nyc:               {"custom:subnet_router == 'nyc'", "ip:country NOT IN ['KP', 'IR']"},
		nycGeoUnset:       {"custom:subnet_router == 'nyc'", "ip:country NOT SET"},
	}

	cases := []attrsCase{
		// tests[0]: {"node:os": "linux", "ip:country": "US"} accepts bbb (the
		// steering gate opens through steering-not-set) and denies nyc-svc.
		{
			name:    "test 0 opens the steering gate",
			posture: steeringNotSet, rules: rules[steeringNotSet],
			attrs: complete(map[string]any{"node:os": "linux", "ip:country": "US"}),
			want:  posture.Satisfied,
			satisfiedHas: []string{
				"custom:subnet_router is unset",
				"ip:country US is not in ['KP', 'IR']",
			},
		},
		{
			name:    "test 0 closes the nyc gate",
			posture: nyc, rules: rules[nyc],
			attrs: complete(map[string]any{"node:os": "linux", "ip:country": "US"}),
			want:  posture.Unsatisfied,
			decidingHas: []string{
				"custom:subnet_router is unset",
			},
		},
		{
			name:    "test 0 closes the nyc-geo-unset gate on country",
			posture: nycGeoUnset, rules: rules[nycGeoUnset],
			attrs: complete(map[string]any{"node:os": "linux", "ip:country": "US"}),
			want:  posture.Unsatisfied,
			decidingHas: []string{
				"custom:subnet_router is unset",
			},
		},
		// tests[1]: {"node:os": "linux"} — the omitted ip:country is unset, so
		// the steering gate opens through steering-not-set-geo-unset.
		{
			name:    "test 1 opens the steering gate through the geo-unset posture",
			posture: steeringNotSetGeo, rules: rules[steeringNotSetGeo],
			attrs: complete(map[string]any{"node:os": "linux"}),
			want:  posture.Satisfied,
			satisfiedHas: []string{
				"custom:subnet_router is unset",
				"ip:country is unset",
			},
		},
		{
			name:    "test 1 fails steering-not-set on the omitted country",
			posture: steeringNotSet, rules: rules[steeringNotSet],
			attrs: complete(map[string]any{"node:os": "linux"}),
			want:  posture.Unsatisfied,
			decidingHas: []string{
				"ip:country is unset",
			},
		},
		// tests[2]: {"node:os": "linux", "ip:country": "KP"} denies both — both
		// steering postures fail on the country.
		{
			name:    "test 2 fails steering-not-set on KP",
			posture: steeringNotSet, rules: rules[steeringNotSet],
			attrs: complete(map[string]any{"node:os": "linux", "ip:country": "KP"}),
			want:  posture.Unsatisfied,
			decidingHas: []string{
				"ip:country KP is in ['KP', 'IR']",
			},
		},
		{
			name:    "test 2 fails steering-geo-unset on KP being set",
			posture: steeringNotSetGeo, rules: rules[steeringNotSetGeo],
			attrs: complete(map[string]any{"node:os": "linux", "ip:country": "KP"}),
			want:  posture.Unsatisfied,
			decidingHas: []string{
				"ip:country is set",
			},
		},
		// tests[3]: {"custom:subnet_router": "nyc", "ip:country": "US"} accepts
		// nyc-svc through posture:nyc and is denied bbb.
		{
			name:    "test 3 opens the nyc gate",
			posture: nyc, rules: rules[nyc],
			attrs: complete(map[string]any{"custom:subnet_router": "nyc", "ip:country": "US"}),
			want:  posture.Satisfied,
			satisfiedHas: []string{
				"custom:subnet_router is nyc",
				"ip:country US is not in ['KP', 'IR']",
			},
		},
		{
			name:    "test 3 closes the steering gate on the set attribute",
			posture: steeringNotSet, rules: rules[steeringNotSet],
			attrs: complete(map[string]any{"custom:subnet_router": "nyc", "ip:country": "US"}),
			want:  posture.Unsatisfied,
			decidingHas: []string{
				"custom:subnet_router is set",
			},
		},
		// tests[5]: {"custom:subnet_router": "nyc", "ip:country": "IR"} denies
		// both.
		{
			name:    "test 5 fails nyc on IR",
			posture: nyc, rules: rules[nyc],
			attrs: complete(map[string]any{"custom:subnet_router": "nyc", "ip:country": "IR"}),
			want:  posture.Unsatisfied,
			decidingHas: []string{
				"ip:country IR is in ['KP', 'IR']",
			},
		},
		// tests[6]: {"custom:subnet_router": "ldn"} denies both.
		{
			name:    "test 6 fails nyc on the wrong router",
			posture: nyc, rules: rules[nyc],
			attrs: complete(map[string]any{"custom:subnet_router": "ldn"}),
			want:  posture.Unsatisfied,
			decidingHas: []string{
				"custom:subnet_router is ldn, not nyc",
			},
		},
	}
	runAttrsCases(t, cases)
}

// TestEvaluatePostureCompleteness pins the completeness contract: without
// the assertion, an omitted attribute is Unknown rather than unset — the
// honesty check keeps for questions about real devices, where "not supplied"
// means "not known".
func TestEvaluatePostureCompleteness(t *testing.T) {
	t.Parallel()

	runAttrsCases(t, []attrsCase{
		{
			name:    "not set on an omitted attribute without completeness",
			posture: "posture:test",
			rules:   []string{"custom:subnet_router NOT SET"},
			attrs:   partial(map[string]any{"node:os": "linux"}),
			want:    posture.Unknown,
			decidingHas: []string{
				"custom:subnet_router was not supplied",
				"not asserted complete",
			},
		},
		{
			name:    "membership on an omitted attribute without completeness",
			posture: "posture:test",
			rules:   []string{"ip:country NOT IN ['KP', 'IR']"},
			attrs:   partial(map[string]any{"ip:country": "KP"}),
			want:    posture.Unsatisfied,
			decidingHas: []string{
				"ip:country KP is in ['KP', 'IR']",
			},
		},
		{
			name:    "an empty map with completeness treats everything as unset",
			posture: "posture:test",
			rules:   []string{"custom:subnet_router NOT SET", "ip:country NOT SET"},
			attrs:   posture.Attrs{Map: map[string]any{}, Complete: true},
			want:    posture.Satisfied,
			satisfiedHas: []string{
				"custom:subnet_router is unset",
				"ip:country is unset",
			},
		},
		{
			// The check probe from the write-up: without the completeness
			// assertion the gate stays indeterminate even though the supplied
			// country fails the second rule — a posture that reads an
			// unsupplied attribute is not judged at all in partial mode.
			name:    "partial mode does not judge a posture reading an unsupplied attribute",
			posture: "posture:steering-not-set",
			rules:   []string{"custom:subnet_router NOT SET", "ip:country NOT IN ['KP', 'IR']"},
			attrs:   partial(map[string]any{"ip:country": "KP"}),
			want:    posture.Unknown,
			decidingHas: []string{
				"custom:subnet_router was not supplied",
			},
		},
		{
			name:    "completeness lets the false rule decide the same posture",
			posture: "posture:steering-not-set",
			rules:   []string{"custom:subnet_router NOT SET", "ip:country NOT IN ['KP', 'IR']"},
			attrs:   complete(map[string]any{"ip:country": "KP"}),
			want:    posture.Unsatisfied,
			decidingHas: []string{
				"ip:country KP is in ['KP', 'IR']",
			},
		},
	})
}

// TestEvaluatePostureUnevaluable pins the two always-unevaluable shapes:
// unparseable expressions and version comparisons. Both must read as
// Unknown, never as a verdict.
func TestEvaluatePostureUnevaluable(t *testing.T) {
	t.Parallel()

	runAttrsCases(t, []attrsCase{
		{
			name:        "unparseable expression",
			posture:     "posture:test",
			rules:       []string{"this is not an expression"},
			attrs:       complete(map[string]any{"node:os": "linux"}),
			want:        posture.Unknown,
			decidingHas: []string{"unsupported posture expression"},
		},
		{
			name:    "version comparison stays unevaluable",
			posture: "posture:test",
			rules:   []string{"node:tsVersion >= '1.8'"},
			attrs:   complete(map[string]any{"node:tsVersion": "1.98.8"}),
			want:    posture.Unknown,
			decidingHas: []string{
				"version comparison", "not evaluated locally",
			},
		},
		{
			name:    "osVersion ordering stays unevaluable",
			posture: "posture:test",
			rules:   []string{"node:osVersion < '14'"},
			attrs:   complete(map[string]any{"node:osVersion": "15.1"}),
			want:    posture.Unknown,
			decidingHas: []string{
				"version comparison", "not evaluated locally",
			},
		},
		{
			name:    "a false rule decides beside an unevaluable sibling",
			posture: "posture:test",
			rules:   []string{"node:tsVersion >= '1.8'", "custom:subnet_router == 'nyc'"},
			attrs:   complete(map[string]any{"custom:subnet_router": "ldn"}),
			want:    posture.Unsatisfied,
			decidingHas: []string{
				"custom:subnet_router is ldn, not nyc",
			},
		},
		{
			name:    "version equality still evaluates",
			posture: "posture:test",
			rules:   []string{"node:tsVersion == '1.40.0'"},
			attrs:   complete(map[string]any{"node:tsVersion": "1.40.0"}),
			want:    posture.Satisfied,
			satisfiedHas: []string{
				"node:tsVersion is 1.40.0",
			},
		},
	})
}

// TestEvaluatePostureOperators sweeps the remaining operator shapes through
// the attrs path.
func TestEvaluatePostureOperators(t *testing.T) {
	t.Parallel()

	runAttrsCases(t, []attrsCase{
		{
			name:    "bare true",
			posture: "posture:test",
			rules:   []string{"custom:approved"},
			attrs:   complete(map[string]any{"custom:approved": true}),
			want:    posture.Satisfied,
			satisfiedHas: []string{
				"custom:approved is true",
			},
		},
		{
			name:        "bare false",
			posture:     "posture:test",
			rules:       []string{"custom:approved"},
			attrs:       complete(map[string]any{"custom:approved": false}),
			want:        posture.Unsatisfied,
			decidingHas: []string{"custom:approved is false"},
		},
		{
			name:        "bare non-boolean is unevaluable",
			posture:     "posture:test",
			rules:       []string{"custom:tier"},
			attrs:       complete(map[string]any{"custom:tier": "gold"}),
			want:        posture.Unknown,
			decidingHas: []string{"not a boolean"},
		},
		{
			name:    "is set on a present attribute",
			posture: "posture:test",
			rules:   []string{"custom:approved IS SET"},
			attrs:   complete(map[string]any{"custom:approved": false}),
			want:    posture.Satisfied,
			satisfiedHas: []string{
				"custom:approved is set",
			},
		},
		{
			name:    "inequality satisfied",
			posture: "posture:test",
			rules:   []string{"node:os != 'windows'"},
			attrs:   complete(map[string]any{"node:os": "linux"}),
			want:    posture.Satisfied,
			satisfiedHas: []string{
				"node:os is linux, not windows",
			},
		},
		{
			name:        "inequality failed",
			posture:     "posture:test",
			rules:       []string{"node:os != 'linux'"},
			attrs:       complete(map[string]any{"node:os": "linux"}),
			want:        posture.Unsatisfied,
			decidingHas: []string{"node:os is linux"},
		},
		{
			name:    "numeric ordering satisfied",
			posture: "posture:test",
			rules:   []string{"custom:score >= 5"},
			attrs:   complete(map[string]any{"custom:score": 7.0}),
			want:    posture.Satisfied,
			satisfiedHas: []string{
				"custom:score 7 > 5",
			},
		},
		{
			name:         "numeric ordering failed renders the actual relationship",
			posture:      "posture:test",
			rules:        []string{"custom:score >= 5"},
			attrs:        complete(map[string]any{"custom:score": 5.0}),
			want:         posture.Satisfied,
			satisfiedHas: []string{"custom:score 5 == 5"},
		},
		{
			name:        "numeric ordering unequal renders less than",
			posture:     "posture:test",
			rules:       []string{"custom:score > 5"},
			attrs:       complete(map[string]any{"custom:score": 2.0}),
			want:        posture.Unsatisfied,
			decidingHas: []string{"custom:score 2 < 5"},
		},
		{
			name:        "ordering a non-number is unevaluable",
			posture:     "posture:test",
			rules:       []string{"custom:tier >= 5"},
			attrs:       complete(map[string]any{"custom:tier": "gold"}),
			want:        posture.Unknown,
			decidingHas: []string{"no ordering"},
		},
		{
			name:    "node os comparison is case insensitive",
			posture: "posture:test",
			rules:   []string{"node:os == 'Linux'"},
			attrs:   complete(map[string]any{"node:os": "LINUX"}),
			want:    posture.Satisfied,
			satisfiedHas: []string{
				"node:os is linux",
			},
		},
	})
}

// TestAttrsSupplied pins the zero-value distinction callers branch on: no
// input at all versus an asserted-complete empty set.
func TestAttrsSupplied(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		attrs posture.Attrs
		want  bool
	}{
		{"zero value is not supplied", posture.Attrs{}, false},
		{"a map is supplied", posture.Attrs{Map: map[string]any{}}, true},
		{"completeness alone is supplied", posture.Attrs{Complete: true}, true},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			if got := testCase.attrs.Supplied(); got != testCase.want {
				t.Errorf("Supplied() = %v; want %v", got, testCase.want)
			}
		})
	}
}
