package posture

import (
	_ "embed"
	"fmt"
	"strings"
	"sync"
)

// DiagnosticKind classifies one posture-expression validation finding.
type DiagnosticKind int

const (
	// DiagnosticUnparseable means the expression is outside the grammar the
	// control plane documents through its error messages: no operator, an
	// unknown operator, a malformed literal or list, an attribute outside the
	// node:/custom:/ip: namespaces, or the bare truthy form applied to a known
	// non-boolean attribute. It is error-level: the server rejects these.
	DiagnosticUnparseable DiagnosticKind = iota
	// DiagnosticUnknownAttribute means a node: or ip: attribute is absent from
	// the known-attribute table. It is warning-level: the table is editorial
	// and the server grows new attributes, so an unknown name may be a stale
	// table rather than a typo. custom: attributes are user-defined and are
	// never checked.
	DiagnosticUnknownAttribute
	// DiagnosticUnknownValue means an ip:country value is outside the recorded
	// country vocabulary. It is error-level, matching the control plane, which
	// rejects the policy over one bad code.
	DiagnosticUnknownValue
)

// ErrorLevel reports whether the kind is one the control plane rejects
// outright. DiagnosticUnknownAttribute is the only warning-level kind: it
// guards a table that goes stale, so it must never block an edit the server
// might accept.
func (k DiagnosticKind) ErrorLevel() bool {
	return k != DiagnosticUnknownAttribute
}

// String returns the stable machine name for a kind.
func (k DiagnosticKind) String() string {
	switch k {
	case DiagnosticUnparseable:
		return "unparseable"
	case DiagnosticUnknownAttribute:
		return "unknown-attribute"
	case DiagnosticUnknownValue:
		return "unknown-value"
	default:
		return "unparseable"
	}
}

// Diagnostic is one validation finding about a posture expression. Reason
// mirrors the control plane's own message wording where the wording is known
// from live probes, so a finding reads the way server-side validate would
// phrase it.
type Diagnostic struct {
	Kind DiagnosticKind
	// Attribute is the posture attribute the finding concerns, when one was
	// identified.
	Attribute string
	// Value is the offending literal, set for DiagnosticUnknownValue.
	Value string
	// Reason is the human-readable explanation.
	Reason string
}

// validOperatorsMessage mirrors the operator list the control plane prints
// when an expression has no recognizable operator, captured verbatim from the
// server's error on 2026-10-02 (Features write-up 03).
const validOperatorsMessage = "valid operators are: !=, <, <=, ==, >, >=, in, is set, not in, not set"

// Validate checks one posture expression against the grammar and the recorded
// vocabularies, returning every diagnostic it finds. A valid expression
// returns nil. The package's three-valued rule applies here too: an expression
// Validate cannot read is reported, never silently passed — callers must treat
// any DiagnosticUnparseable as error-level.
//
// The check is deliberately asymmetric across namespaces. node: and ip:
// attributes are checked against the known-attribute table, and ip:country
// values against the recorded country vocabulary, because both namespaces are
// server-defined. custom: attributes are user-defined: no name or value of
// theirs is ever flagged.
func Validate(expression string) []Diagnostic {
	trimmed := strings.TrimSpace(expression)
	attribute, rest, ok := splitRule(trimmed)
	if !ok {
		return []Diagnostic{{Kind: DiagnosticUnparseable, Reason: "empty posture expression"}}
	}
	if !validAttribute(attribute) {
		return invalidAttributeDiagnostics(attribute, rest)
	}

	if rest == "" {
		return bareFormDiagnostics(attribute)
	}

	operator, operand, ok := splitOperator(rest)
	if !ok {
		return []Diagnostic{{
			Kind:      DiagnosticUnparseable,
			Attribute: attribute,
			Reason:    unparseableOperatorReason(rest),
		}}
	}

	var diagnostics []Diagnostic
	if known, checked := knownAttribute(attribute); checked {
		diagnostics = append(diagnostics, known...)
	}
	switch operator {
	case opIn, opNotIn:
		list, listOK := parseList(operand)
		if !listOK {
			return append(diagnostics, Diagnostic{
				Kind:      DiagnosticUnparseable,
				Attribute: attribute,
				Reason:    fmt.Sprintf("expected a bracketed list of literals, found: %q", operand),
			})
		}
		return append(diagnostics, countryListDiagnostics(attribute, list)...)
	case opIsSet, opNotSet:
		return diagnostics
	default:
		literal, literalOK := parseLiteral(operand)
		if !literalOK {
			return append(diagnostics, Diagnostic{
				Kind:      DiagnosticUnparseable,
				Attribute: attribute,
				Reason: fmt.Sprintf(
					"expected a quoted string, number, or boolean literal, found: %q", operand),
			})
		}
		if attribute == ipCountryAttribute {
			if diagnostic, bad := countryValueDiagnostic(attribute, literal, -1); bad {
				return append(diagnostics, diagnostic)
			}
		}
		return diagnostics
	}
}

// invalidAttributeDiagnostics reports an attribute token outside the three
// grammar namespaces. When the rest of the expression has no recognizable
// operator either, the control plane's own wording for that failure — which it
// emits before judging the attribute, as its message for "this is not an
// expression" shows — is the more useful reason, so it wins.
func invalidAttributeDiagnostics(attribute, rest string) []Diagnostic {
	if rest != "" {
		if _, _, operatorOK := splitOperator(rest); !operatorOK {
			return []Diagnostic{{
				Kind:      DiagnosticUnparseable,
				Attribute: attribute,
				Reason:    unparseableOperatorReason(rest),
			}}
		}
	}
	return []Diagnostic{{
		Kind:      DiagnosticUnparseable,
		Attribute: attribute,
		Reason: fmt.Sprintf(
			"unsupported attribute %q: posture attributes are in the node:, custom:, or ip: namespace",
			attribute),
	}}
}

// unparseableOperatorReason mirrors the control plane's operator error. The
// server quotes the first three words of the would-be operator — "this is not
// an expression" came back as `found: "is not an"` — so the same truncation is
// applied here; with only that one observed message, three words is the best
// reading of its truncation rule.
func unparseableOperatorReason(rest string) string {
	const quotedWords = 3
	fields := strings.Fields(rest)
	if len(fields) > quotedWords {
		fields = fields[:quotedWords]
	}
	return fmt.Sprintf("expected an operator, found: %q, %s",
		strings.Join(fields, " "), validOperatorsMessage)
}

// bareFormDiagnostics applies the control plane's bare-form rule, captured
// verbatim on 2026-10-02: the server reads a bare attribute as an implicit
// comparison to true and rejects it for a built-in attribute that is not
// boolean. The bare form on a custom: or unknown attribute is not checked —
// the server accepts it, and the known-attribute table is not authoritative
// enough to say otherwise.
func bareFormDiagnostics(attribute string) []Diagnostic {
	kind, known := knownAttributes[attribute]
	if !known || kind == attributeBool {
		return nil
	}
	return []Diagnostic{{
		Kind:      DiagnosticUnparseable,
		Attribute: attribute,
		Reason: fmt.Sprintf(
			"built-in attribute %q can only be compared to %s, got bool: true",
			attribute, kind),
	}}
}

// knownAttribute reports a node: or ip: attribute the known-attribute table
// does not list. It is warning-level: the table is editorial and goes stale as
// the server grows attributes, so a missing name is reported the way the
// control plane phrases it but must never be treated as proof the attribute is
// wrong.
func knownAttribute(attribute string) ([]Diagnostic, bool) {
	if !strings.HasPrefix(attribute, nodePrefix) && !strings.HasPrefix(attribute, ipPrefix) {
		return nil, false
	}
	if _, known := knownAttributes[attribute]; known {
		return nil, false
	}
	return []Diagnostic{{
		Kind:      DiagnosticUnknownAttribute,
		Attribute: attribute,
		Reason:    fmt.Sprintf("attribute %q does not exist", attribute),
	}}, true
}

// attributeKind is the value type the control plane assigns a built-in
// posture attribute. The names are the server's own words for them, lifted
// from its type-mismatch message ("can only be compared to string").
type attributeKind string

const (
	attributeString  attributeKind = "string"
	attributeVersion attributeKind = "version"
	attributeBool    attributeKind = "bool"
	attributeNumber  attributeKind = "number"
)

// ipCountryAttribute is the one attribute with a recorded value vocabulary.
const ipCountryAttribute = "ip:country"

// knownAttributes is the editorial table of server-defined posture attributes
// this package recognizes. It is deliberately small and hand-maintained: the
// server grows attributes without notice, so absence from this table is a
// warning (DiagnosticUnknownAttribute), never an error.
//
//nolint:gochecknoglobals // a fixed, read-only vocabulary table; the AX Tier-2 guard test pins it.
var knownAttributes = map[string]attributeKind{
	"node:os":          attributeString,
	"node:osVersion":   attributeVersion,
	"node:tsVersion":   attributeVersion,
	"node:app":         attributeString,
	ipCountryAttribute: attributeString,
}

//go:embed testdata/ip_country_vocabulary.txt
var ipCountryVocabularyData string

// ipCountryVocabulary memoizes the parsed fixture. The fixture file is the
// source of truth — it is the control plane's own accepted-country list,
// captured live on 2026-10-02 — and the guard test in validate_test.go pins
// this set against it.
//
//nolint:gochecknoglobals // sync.OnceValues must be package-level; memoizes the embedded fixture for process lifetime.
var ipCountryVocabulary = sync.OnceValues(func() (map[string]bool, []string) {
	set := make(map[string]bool)
	var ordered []string
	for line := range strings.Lines(ipCountryVocabularyData) {
		code := strings.TrimSpace(line)
		if code == "" || strings.HasPrefix(code, "#") {
			continue
		}
		if !set[code] {
			set[code] = true
			ordered = append(ordered, code)
		}
	}
	return set, ordered
})

// countryVocabularyMessage renders the valid-values tail the control plane
// appends to a country error: the full recorded list, in fixture order.
func countryVocabularyMessage() string {
	_, ordered := ipCountryVocabulary()
	return "valid values: " + strings.Join(ordered, ", ")
}

// countryListDiagnostics flags every string element of an ip:country
// membership list that the recorded vocabulary does not contain, mirroring the
// control plane's "list value at index N" wording. Non-string elements are not
// country codes at all; the server has not been probed for them, so they are
// left unchecked rather than guessed at.
func countryListDiagnostics(attribute string, list []any) []Diagnostic {
	if attribute != ipCountryAttribute {
		return nil
	}
	var diagnostics []Diagnostic
	for index, element := range list {
		if diagnostic, bad := countryValueDiagnostic(attribute, element, index); bad {
			diagnostics = append(diagnostics, diagnostic)
		}
	}
	return diagnostics
}

// countryValueDiagnostic flags one ip:country literal outside the recorded
// vocabulary. A negative index means the literal came from a scalar
// comparison, which has no "list value at index" prefix in the reason.
func countryValueDiagnostic(attribute string, literal any, index int) (Diagnostic, bool) {
	code, isString := literal.(string)
	if !isString {
		return Diagnostic{}, false
	}
	set, _ := ipCountryVocabulary()
	if set[code] {
		return Diagnostic{}, false
	}
	reason := fmt.Sprintf("unexpected value %q; %s", code, countryVocabularyMessage())
	if index >= 0 {
		reason = fmt.Sprintf("list value at index %d: %s", index, reason)
	}
	return Diagnostic{
		Kind:      DiagnosticUnknownValue,
		Attribute: attribute,
		Value:     code,
		Reason:    reason,
	}, true
}
