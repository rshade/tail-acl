// Package posture evaluates Tailscale device-posture rule expressions against a
// captured device's facts. It is pure: no I/O, no clock, no environment, and it
// deliberately imports nothing outside the standard library so the evaluator
// adds zero audit surface.
//
// Unknown is a first-class outcome. An expression this package cannot evaluate,
// or an attribute the capture does not carry, is reported as unevaluable and is
// never folded into a pass or a failure — a wrong verdict about who satisfies a
// posture is worse than an honest "could not tell".
package posture

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"
)

// State is the three-valued verdict of a posture evaluation. Unknown is the
// zero value so a Verdict nobody filled in reads as unevaluable.
type State int

const (
	// Unknown means the posture could not be evaluated from the captured facts.
	Unknown State = iota
	// Satisfied means every rule of the posture held.
	Satisfied
	// Unsatisfied means at least one rule of the posture definitely failed.
	Unsatisfied
)

// String returns the stable machine name for a state.
func (s State) String() string {
	switch s {
	case Unknown:
		return "unknown"
	case Satisfied:
		return "satisfied"
	case Unsatisfied:
		return "unsatisfied"
	default:
		return "unknown"
	}
}

// MarshalText serializes State by name rather than numeric rank.
func (s State) MarshalText() ([]byte, error) { return []byte(s.String()), nil }

// Facts is everything the evaluator may read about one device.
type Facts struct {
	// OS and ClientVersion come from the devices listing, so they resolve
	// node:os and node:tsVersion even when attributes were not collected.
	OS            string
	ClientVersion string
	// Attributes is the device's collected posture attributes, keyed as the
	// policy names them ("node:os", "custom:deviceApproved").
	Attributes map[string]any
	// Expiries carries each attribute's expiry, when it has one.
	Expiries map[string]time.Time
	// Collected reports that attribute collection was requested and attempted
	// for this device.
	Collected bool
	// CollectError is non-empty when this device's attribute fetch failed, so
	// its attributes are unavailable rather than unset.
	CollectError string
}

// Verdict is one posture's evaluation plus the fact that decided it.
type Verdict struct {
	Posture string
	State   State
	// Reason names the failing expression, or why the posture could not be
	// evaluated. It is empty exactly when the posture is Satisfied.
	Reason string
}

// Attribute namespaces and the two attributes the devices listing carries.
const (
	nodePrefix   = "node:"
	customPrefix = "custom:"
	ipPrefix     = "ip:"

	nodeOSAttribute      = "node:os"
	nodeVersionAttribute = "node:tsVersion"
)

// Supported operators. The membership and set keywords are matched
// case-insensitively.
const (
	opEqual        = "=="
	opNotEqual     = "!="
	opLess         = "<"
	opLessEqual    = "<="
	opGreater      = ">"
	opGreaterEqual = ">="
	opIn           = "IN"
	opNotIn        = "NOT IN"
	opIsSet        = "IS SET"
	opNotSet       = "NOT SET"
	// opBare is the truthy form, which takes no literal.
	opBare = ""
)

// Evaluate reports whether facts satisfy the posture named name, whose rules
// come from ACL.Postures. Rules are ANDed with Kleene three-valued logic: one
// Unsatisfied rule makes the posture Unsatisfied even when other rules are
// Unknown, and otherwise any Unknown makes it Unknown. That ordering is
// deliberate — it is the only composition that lets a definite failure survive
// alongside an unevaluable sibling rule, so real gaps still surface on a tailnet
// whose postures mix evaluable and unevaluable attributes.
//
// An empty rule list is a vacuous conjunction and is Satisfied: a posture that
// states no requirement constrains nothing. A posture the policy never defines
// is a different case that never reaches Evaluate — the caller reports an
// undefined posture as Unknown before it has any rules to evaluate.
//
// now is the snapshot's capture time and is used only to decide whether an
// attribute's expiry has passed.
func Evaluate(name string, rules []string, facts Facts, now time.Time) Verdict {
	var unsatisfiedReason, unknownReason string
	for _, rule := range rules {
		state, reason := evaluateRule(rule, facts, now)
		switch state {
		case Unsatisfied:
			if unsatisfiedReason == "" {
				unsatisfiedReason = reason
			}
		case Unknown:
			if unknownReason == "" {
				unknownReason = reason
			}
		case Satisfied:
		}
	}
	switch {
	case unsatisfiedReason != "":
		return Verdict{Posture: name, State: Unsatisfied, Reason: unsatisfiedReason}
	case unknownReason != "":
		return Verdict{Posture: name, State: Unknown, Reason: unknownReason}
	default:
		return Verdict{Posture: name, State: Satisfied}
	}
}

// ReferencedAttributes returns the sorted, distinct attribute names rules read.
// It is how a caller decides whether a posture depends on an attribute a device
// cannot report. An attribute is reported even when the rest of its expression
// is unsupported, because the dependency is real either way.
func ReferencedAttributes(rules []string) []string {
	seen := make(map[string]bool, len(rules))
	for _, rule := range rules {
		attribute, _, ok := splitRule(rule)
		if !ok || !validAttribute(attribute) {
			continue
		}
		seen[attribute] = true
	}
	if len(seen) == 0 {
		return nil
	}
	attributes := make([]string, 0, len(seen))
	for attribute := range seen {
		attributes = append(attributes, attribute)
	}
	slices.Sort(attributes)
	return attributes
}

// evaluateRule evaluates one rule expression.
func evaluateRule(rule string, facts Facts, now time.Time) (State, string) {
	trimmed := strings.TrimSpace(rule)
	parsed, ok := parseRule(trimmed)
	if !ok {
		return Unknown, "unsupported posture expression: " + trimmed
	}

	value, resolution, reason := resolveAttribute(parsed.attribute, facts, now)
	switch resolution {
	case resolutionUnknown:
		return Unknown, reason
	case resolutionAbsent:
		// NOT SET is the one operator an absent attribute satisfies: it is the
		// question "is this unset?", answered directly by the capture.
		if parsed.operator == opNotSet {
			return Satisfied, ""
		}
		// A negated comparison against an absent attribute is not evaluated:
		// claiming "unset" satisfies a negation would be a guess about
		// Tailscale's semantics rather than a reading of the captured facts.
		if parsed.operator == opNotEqual || parsed.operator == opNotIn {
			return Unknown, reason + "; a negated comparison against an unset attribute is not evaluated"
		}
		return Unsatisfied, reason
	case resolutionResolved:
	}
	// The set operators decide on resolution alone; the value itself is
	// irrelevant to whether the attribute is set.
	switch parsed.operator {
	case opIsSet:
		return Satisfied, ""
	case opNotSet:
		return Unsatisfied, unsatisfiedReason(trimmed, parsed.attribute, value)
	}
	return compare(parsed, value, trimmed)
}

// rule is a parsed posture expression.
type rule struct {
	attribute string
	operator  string
	literal   any
	list      []any
}

// parseRule parses the supported grammar and reports whether expression is in
// it. Anything outside the grammar is rejected rather than guessed at:
//
//	rule       := attr op literal | attr membership list | attr setop | attr
//	attr       := "node:" NAME | "custom:" NAME | "ip:" NAME
//	op         := "==" | "!=" | "<" | "<=" | ">" | ">="
//	membership := "IN" | "NOT IN"      (case-insensitive)
//	setop      := "IS SET" | "NOT SET" (case-insensitive)
//	list       := "[" literal ("," literal)* "]"
//	literal    := '"'...'"' | "'"..."'" | number | true | false
func parseRule(expression string) (rule, bool) {
	attribute, rest, ok := splitRule(expression)
	if !ok || !validAttribute(attribute) {
		return rule{}, false
	}
	if rest == "" {
		return rule{attribute: attribute, operator: opBare}, true
	}
	operator, operand, ok := splitOperator(rest)
	if !ok {
		return rule{}, false
	}
	switch operator {
	case opIsSet, opNotSet:
		return rule{attribute: attribute, operator: operator}, true
	case opIn, opNotIn:
		list, listOK := parseList(operand)
		if !listOK {
			return rule{}, false
		}
		return rule{attribute: attribute, operator: operator, list: list}, true
	}
	literal, literalOK := parseLiteral(operand)
	if !literalOK {
		return rule{}, false
	}
	return rule{attribute: attribute, operator: operator, literal: literal}, true
}

// splitRule takes the leading attribute name off expression and returns the
// remainder. It stops at the first rune an attribute name cannot contain, so an
// operator that runs straight into the name still separates cleanly.
func splitRule(expression string) (string, string, bool) {
	trimmed := strings.TrimSpace(expression)
	end := len(trimmed)
	for index, character := range trimmed {
		if !isAttributeRune(character) {
			end = index
			break
		}
	}
	attribute := trimmed[:end]
	return attribute, strings.TrimSpace(trimmed[end:]), attribute != ""
}

func isAttributeRune(character rune) bool {
	switch {
	case character >= 'a' && character <= 'z',
		character >= 'A' && character <= 'Z',
		character >= '0' && character <= '9':
		return true
	default:
		return character == ':' || character == '_' || character == '-' || character == '.'
	}
}

// validAttribute reports whether name is an attribute the grammar admits: one
// of the three known namespaces followed by a non-empty name.
func validAttribute(name string) bool {
	for _, prefix := range []string{nodePrefix, customPrefix, ipPrefix} {
		if after, found := strings.CutPrefix(name, prefix); found {
			return after != "" && !strings.Contains(after, ":")
		}
	}
	return false
}

// splitOperator takes the operator off rest and returns the operand. Membership
// keywords are checked before the symbolic operators, and the two-character
// symbols before their one-character prefixes, so "<=" never parses as "<".
// The set operators take no operand, so they match only when they are the whole
// remainder: anything after them is rejected rather than silently dropped.
func splitOperator(rest string) (string, string, bool) {
	if after, found := cutKeyword(rest, "NOT"); found {
		if operand, inFound := cutKeyword(after, opIn); inFound {
			return opNotIn, operand, true
		}
		if isTerminalKeyword(after, "SET") {
			return opNotSet, "", true
		}
		return "", "", false
	}
	if after, found := cutKeyword(rest, opIn); found {
		return opIn, after, true
	}
	if isSetOperator(rest) {
		return opIsSet, "", true
	}
	for _, candidate := range []string{opEqual, opNotEqual, opLessEqual, opGreaterEqual, opLess, opGreater} {
		if after, found := strings.CutPrefix(rest, candidate); found {
			return candidate, strings.TrimSpace(after), true
		}
	}
	return "", "", false
}

// isSetOperator reports whether text is exactly the two-word IS SET operator,
// case-insensitively and tolerant of interior whitespace.
func isSetOperator(text string) bool {
	fields := strings.Fields(text)
	return len(fields) == 2 &&
		strings.EqualFold(fields[0], "IS") && strings.EqualFold(fields[1], "SET")
}

// isTerminalKeyword reports whether text is exactly keyword,
// case-insensitively. Unlike cutKeyword it matches at the end of the
// expression, which is where the no-operand operators sit.
func isTerminalKeyword(text, keyword string) bool {
	return strings.EqualFold(strings.TrimSpace(text), keyword)
}

// cutKeyword removes a case-insensitive keyword prefix from text, requiring a
// word boundary after it so an attribute or literal starting with the same
// letters is not mistaken for the keyword.
func cutKeyword(text, keyword string) (string, bool) {
	if len(text) < len(keyword) || !strings.EqualFold(text[:len(keyword)], keyword) {
		return text, false
	}
	remainder := text[len(keyword):]
	if remainder == "" {
		return "", false
	}
	if boundary := remainder[0]; boundary != ' ' && boundary != '\t' && boundary != '[' {
		return text, false
	}
	return strings.TrimSpace(remainder), true
}

// parseLiteral parses a single literal that must consume all of text. Requiring
// full consumption is what rejects trailing garbage and conjunctions.
func parseLiteral(text string) (any, bool) {
	const minQuotedLength = 2
	if text == "" {
		return nil, false
	}
	if quote := text[0]; quote == '"' || quote == '\'' {
		if len(text) < minQuotedLength || text[len(text)-1] != quote {
			return nil, false
		}
		inner := text[1 : len(text)-1]
		if strings.ContainsRune(inner, rune(quote)) {
			return nil, false
		}
		return inner, true
	}
	switch text {
	case "true":
		return true, true
	case "false":
		return false, true
	}
	if number, err := strconv.ParseFloat(text, 64); err == nil {
		return number, true
	}
	return nil, false
}

// parseList parses a bracketed literal list that must consume all of text. An
// empty list is rejected: it can never match anything, so it is far more likely
// a policy mistake than an intent this package should silently honour.
func parseList(text string) ([]any, bool) {
	const minListLength = 2
	if len(text) < minListLength || text[0] != '[' || text[len(text)-1] != ']' {
		return nil, false
	}
	inner := strings.TrimSpace(text[1 : len(text)-1])
	if inner == "" {
		return nil, false
	}
	elements, ok := splitListElements(inner)
	if !ok {
		return nil, false
	}
	values := make([]any, 0, len(elements))
	for _, element := range elements {
		value, valueOK := parseLiteral(strings.TrimSpace(element))
		if !valueOK {
			return nil, false
		}
		values = append(values, value)
	}
	return values, true
}

// splitListElements splits a list body on commas that are not inside a quoted
// literal.
func splitListElements(inner string) ([]string, bool) {
	var elements []string
	var current strings.Builder
	var quote byte
	for index := range len(inner) {
		character := inner[index]
		switch {
		case quote != 0:
			if character == quote {
				quote = 0
			}
			current.WriteByte(character)
		case character == '"' || character == '\'':
			quote = character
			current.WriteByte(character)
		case character == ',':
			elements = append(elements, current.String())
			current.Reset()
		default:
			current.WriteByte(character)
		}
	}
	if quote != 0 {
		return nil, false
	}
	return append(elements, current.String()), true
}

// resolution reports how an attribute lookup ended.
type resolution int

const (
	// resolutionResolved means a value was found.
	resolutionResolved resolution = iota
	// resolutionAbsent means the attribute is genuinely unset or expired: the
	// capture is complete and simply does not carry a value.
	resolutionAbsent
	// resolutionUnknown means the value could not be determined from this
	// capture, so no verdict may rest on it.
	resolutionUnknown
)

// resolveAttribute finds the value of name in facts.
//
// A successfully collected attribute wins, because it is the control plane's own
// posture-evaluation input. The devices listing is the fallback, and carries
// only node:os and node:tsVersion. When neither supplies a value, the reason
// distinguishes the three causes an auditor must tell apart: attributes were
// never collected, this device's fetch failed, or the attribute really is unset.
func resolveAttribute(name string, facts Facts, now time.Time) (any, resolution, string) {
	if facts.Collected && facts.CollectError == "" {
		if value, present := facts.Attributes[name]; present {
			return applyExpiry(name, value, facts, now)
		}
	}
	if value, present := deviceFallback(name, facts); present {
		return value, resolutionResolved, ""
	}
	switch {
	case !facts.Collected:
		return nil, resolutionUnknown, name + " requires -posture-attributes to evaluate"
	case facts.CollectError != "":
		return nil, resolutionUnknown, "posture attributes unavailable for this device: " + facts.CollectError
	case strings.HasPrefix(name, nodePrefix) || strings.HasPrefix(name, ipPrefix):
		// An intrinsic device fact the capture does not carry is missing data,
		// not an unset attribute: reporting it as unset would claim the device
		// fails a posture it may well satisfy. The devices listing carries no
		// ip:* GeoIP fact, so ip: attributes are missing data here too.
		return nil, resolutionUnknown, name + " is not carried by the devices listing"
	default:
		return nil, resolutionAbsent, name + " is not set"
	}
}

// applyExpiry decides whether a collected value is still live.
func applyExpiry(name string, value any, facts Facts, now time.Time) (any, resolution, string) {
	expiry, hasExpiry := facts.Expiries[name]
	if !hasExpiry || expiry.IsZero() {
		return value, resolutionResolved, ""
	}
	if now.IsZero() {
		return nil, resolutionUnknown, name + " has an expiry but the snapshot has no capture time to compare it against"
	}
	if !expiry.After(now) {
		return nil, resolutionAbsent, fmt.Sprintf("%s expired at %s", name, expiry.Format(time.RFC3339))
	}
	return value, resolutionResolved, ""
}

// deviceFallback resolves the two attributes the devices listing carries.
func deviceFallback(name string, facts Facts) (any, bool) {
	switch name {
	case nodeOSAttribute:
		return facts.OS, facts.OS != ""
	case nodeVersionAttribute:
		return facts.ClientVersion, facts.ClientVersion != ""
	default:
		return nil, false
	}
}

// compare applies parsed's operator to the resolved value.
func compare(parsed rule, value any, expression string) (State, string) {
	normalized := normalize(parsed.attribute, value)
	switch parsed.operator {
	case opBare:
		return compareBare(parsed.attribute, normalized, expression)
	case opEqual, opNotEqual:
		return compareEquality(parsed, normalized, expression)
	case opIn, opNotIn:
		return compareMembership(parsed, normalized, expression)
	default:
		return compareOrdered(parsed, normalized, expression)
	}
}

// normalize applies the per-attribute normalization the API's own shapes
// require: node:os carries no documented case guarantee, and a real
// ClientVersion carries a build suffix ("1.98.8-t1241b225b-g0520dfda5") that no
// posture literal ever names.
func normalize(attribute string, value any) any {
	text, isText := value.(string)
	if !isText {
		return value
	}
	switch attribute {
	case nodeOSAttribute:
		return strings.ToLower(text)
	case nodeVersionAttribute:
		return truncateVersion(text)
	default:
		return value
	}
}

func truncateVersion(version string) string {
	base, _, _ := strings.Cut(version, "-")
	return base
}

// normalizeLiteral applies the same normalization to a literal so both sides of
// a comparison are shaped alike.
func normalizeLiteral(attribute string, literal any) any {
	if attribute != nodeOSAttribute {
		return literal
	}
	if text, isText := literal.(string); isText {
		return strings.ToLower(text)
	}
	return literal
}

func compareBare(attribute string, value any, expression string) (State, string) {
	truthy, isBool := value.(bool)
	if !isBool {
		return Unknown, fmt.Sprintf(
			"%s cannot be evaluated: %s is %s, which is not a boolean",
			expression, attribute, render(value),
		)
	}
	if truthy {
		return Satisfied, ""
	}
	return Unsatisfied, unsatisfiedReason(expression, attribute, value)
}

func compareEquality(parsed rule, value any, expression string) (State, string) {
	equal := valuesEqual(value, normalizeLiteral(parsed.attribute, parsed.literal))
	if equal == (parsed.operator == opEqual) {
		return Satisfied, ""
	}
	return Unsatisfied, unsatisfiedReason(expression, parsed.attribute, value)
}

func compareMembership(parsed rule, value any, expression string) (State, string) {
	member := false
	for _, element := range parsed.list {
		if valuesEqual(value, normalizeLiteral(parsed.attribute, element)) {
			member = true
			break
		}
	}
	if member == (parsed.operator == opIn) {
		return Satisfied, ""
	}
	return Unsatisfied, unsatisfiedReason(expression, parsed.attribute, value)
}

// compareOrdered applies an ordered operator. Only numbers and node:tsVersion
// have an ordering this package will assert; anything else is Unknown rather
// than a guess at what "less than" means for a bool or a free-form string.
func compareOrdered(parsed rule, value any, expression string) (State, string) {
	if parsed.attribute == nodeVersionAttribute {
		return compareVersions(parsed, value, expression)
	}
	left, leftOK := toNumber(value)
	right, rightOK := toNumber(parsed.literal)
	if !leftOK || !rightOK {
		return Unknown, fmt.Sprintf(
			"%s cannot be evaluated: %s is %s, which has no ordering",
			expression, parsed.attribute, render(value),
		)
	}
	return orderedResult(parsed, compareFloat(left, right), value, expression)
}

func compareVersions(parsed rule, value any, expression string) (State, string) {
	actualText := plainText(value)
	actual, actualOK := parseVersion(actualText)
	if !actualOK {
		return Unknown, unparseableVersion(expression, actualText)
	}
	literalText := plainText(parsed.literal)
	wanted, wantedOK := parseVersion(literalText)
	if !wantedOK {
		return Unknown, unparseableVersion(expression, literalText)
	}
	return orderedResult(parsed, compareVersionFields(actual, wanted), value, expression)
}

// plainText renders value as an unquoted string. Version parsing needs the bare
// text, where render deliberately quotes strings for use in a reason.
func plainText(value any) string {
	if text, isText := value.(string); isText {
		return text
	}
	if number, ok := toNumber(value); ok {
		return strconv.FormatFloat(number, 'f', -1, 64)
	}
	return fmt.Sprintf("%v", value)
}

func unparseableVersion(expression, value string) string {
	return fmt.Sprintf("%s cannot be evaluated: %q is not a dotted-integer version", expression, value)
}

// orderedResult turns a three-way comparison into a verdict for the operator.
func orderedResult(parsed rule, ordering int, value any, expression string) (State, string) {
	satisfied := false
	switch parsed.operator {
	case opLess:
		satisfied = ordering < 0
	case opLessEqual:
		satisfied = ordering <= 0
	case opGreater:
		satisfied = ordering > 0
	case opGreaterEqual:
		satisfied = ordering >= 0
	}
	if satisfied {
		return Satisfied, ""
	}
	return Unsatisfied, unsatisfiedReason(expression, parsed.attribute, value)
}

func unsatisfiedReason(expression, attribute string, value any) string {
	return fmt.Sprintf("%s is not satisfied: %s is %s", expression, attribute, render(value))
}

// parseVersion splits a dotted-integer version into its fields. A field that is
// not an integer makes the whole version unparseable, so a release-track string
// like "unstable" is reported rather than silently ordered.
func parseVersion(version string) ([]int, bool) {
	fields := strings.Split(truncateVersion(strings.TrimSpace(version)), ".")
	numbers := make([]int, 0, len(fields))
	for _, field := range fields {
		number, err := strconv.Atoi(field)
		if err != nil {
			return nil, false
		}
		numbers = append(numbers, number)
	}
	if len(numbers) == 0 {
		return nil, false
	}
	return numbers, true
}

// compareVersionFields compares dotted-integer versions field by field, with a
// missing field counting as zero so "1.40" and "1.40.0" are the same version.
func compareVersionFields(left, right []int) int {
	for index := range max(len(left), len(right)) {
		var leftField, rightField int
		if index < len(left) {
			leftField = left[index]
		}
		if index < len(right) {
			rightField = right[index]
		}
		if leftField != rightField {
			return compareInt(leftField, rightField)
		}
	}
	return 0
}

func compareInt(left, right int) int {
	if left < right {
		return -1
	}
	if left > right {
		return 1
	}
	return 0
}

func compareFloat(left, right float64) int {
	if left < right {
		return -1
	}
	if left > right {
		return 1
	}
	return 0
}

// valuesEqual compares two literal values. Numbers compare numerically across
// the int and float shapes a JSON decode can produce; values of different kinds
// are simply unequal.
func valuesEqual(left, right any) bool {
	if leftNumber, leftOK := toNumber(left); leftOK {
		rightNumber, rightOK := toNumber(right)
		return rightOK && leftNumber == rightNumber
	}
	switch typed := left.(type) {
	case string:
		other, ok := right.(string)
		return ok && typed == other
	case bool:
		other, ok := right.(bool)
		return ok && typed == other
	default:
		return false
	}
}

// toNumber converts the numeric shapes a JSON decode or a Go literal can
// produce into a float64. A bool is deliberately not numeric.
func toNumber(value any) (float64, bool) {
	switch typed := value.(type) {
	case float64:
		return typed, true
	case float32:
		return float64(typed), true
	case int:
		return float64(typed), true
	case int32:
		return float64(typed), true
	case int64:
		return float64(typed), true
	default:
		return 0, false
	}
}

// render formats a value for a reason string.
func render(value any) string {
	switch typed := value.(type) {
	case nil:
		return "unset"
	case string:
		return strconv.Quote(typed)
	case bool:
		return strconv.FormatBool(typed)
	default:
		if number, ok := toNumber(value); ok {
			return strconv.FormatFloat(number, 'f', -1, 64)
		}
		return fmt.Sprintf("%v", typed)
	}
}
