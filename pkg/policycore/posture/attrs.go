package posture

import (
	"fmt"
	"strings"
)

// Attrs is an explicit attribute set for posture evaluation, supplied by a
// caller that knows what a device carries — a policy test's srcPostureAttrs,
// or a reachability query's --posture-attr flags. It is the posture
// counterpart of policycore's roster pattern: Complete asserts the map is
// authoritative, so an attribute absent from it is definitely unset, and the
// assertion is the caller's to make — it is never inferred from the map
// being non-nil.
type Attrs struct {
	// Map is the attribute set, keyed as the policy names attributes
	// ("node:os", "custom:deviceApproved").
	Map map[string]any
	// Complete asserts that what Map omits is unset. With it, an absent
	// attribute fails every comparison except NOT SET, which it satisfies —
	// the control plane's semantics for a test's srcPostureAttrs, verified
	// against the server on 2026-10-02. Without it, an absent attribute the
	// expression needs yields Unknown rather than a guess.
	Complete bool
}

// Supplied reports whether the caller supplied any attribute input at all.
// The zero Attrs means "no attributes were given", which callers report
// through their legacy indeterminate path rather than as an evaluation.
func (a Attrs) Supplied() bool {
	return a.Map != nil || a.Complete
}

// RuleOutcome is one expression's verdict against an explicit attribute set.
// Reason is a statement of the fact that decided it — "ip:country KP is in
// ['KP', 'IR']" — so a caller can compose "..., so posture:X fails" without
// parsing prose back out of a sentence.
type RuleOutcome struct {
	Expression string
	Attribute  string
	State      State
	Reason     string
	// MissingAttribute marks the one Unknown cause that is about the caller's
	// input rather than the expression: the attribute was not supplied and the
	// set is not asserted complete. Outcome.State treats it more conservatively
	// than any other Unknown.
	MissingAttribute bool
}

// Outcome is one posture's evaluation against an explicit attribute
// set: a verdict per expression, in expression order.
type Outcome struct {
	Posture  string
	Rules    []RuleOutcome
	complete bool
}

// State folds the rule verdicts. With the completeness assertion a decidably
// false rule decides the posture even beside an unevaluable sibling — false
// AND anything is false — so Unsatisfied wins over Unknown, the same ordering
// Evaluate's Kleene composition uses.
//
// Without the assertion the fold is more conservative: a posture that reads
// an attribute the caller never supplied is not judged at all, and Unknown
// wins over Unsatisfied. "Not supplied" means "not known", not "unset", and
// the contract for a partial attribute set is that only fully-known postures
// are decided — the honesty the reachability check has always kept for
// questions about real devices.
func (o Outcome) State() State {
	var sawUnsatisfied, sawUnknown, sawMissing bool
	for _, rule := range o.Rules {
		switch rule.State {
		case Unsatisfied:
			sawUnsatisfied = true
		case Unknown:
			sawUnknown = true
			if rule.MissingAttribute {
				sawMissing = true
			}
		case Satisfied:
		}
	}
	if sawMissing && !o.complete {
		return Unknown
	}
	switch {
	case sawUnsatisfied:
		return Unsatisfied
	case sawUnknown:
		return Unknown
	default:
		return Satisfied
	}
}

// DecidingRule returns the rule that settled or clouded the posture. In
// partial mode a missing-attribute Unknown decides ahead of any Unsatisfied
// rule, matching State; otherwise the first Unsatisfied rule wins, else the
// first Unknown rule. The second return is false exactly when the posture is
// Satisfied.
func (o Outcome) DecidingRule() (RuleOutcome, bool) {
	if !o.complete {
		for index := range o.Rules {
			if o.Rules[index].State == Unknown && o.Rules[index].MissingAttribute {
				return o.Rules[index], true
			}
		}
	}
	var unknown *RuleOutcome
	for index := range o.Rules {
		switch o.Rules[index].State {
		case Unsatisfied:
			return o.Rules[index], true
		case Unknown:
			if unknown == nil {
				unknown = &o.Rules[index]
			}
		case Satisfied:
		}
	}
	if unknown != nil {
		return *unknown, true
	}
	return RuleOutcome{}, false
}

// EvaluatePosture evaluates one posture's rules against an explicit
// attribute set, ANDing them the way the control plane does. It exists
// alongside Evaluate, which answers a different question — what a captured
// device provably satisfies — and whose Kleene behavior is unchanged.
//
// The semantics here are the server's, verified against the control plane on
// 2026-10-02: an unset attribute fails every comparison, including != and
// NOT IN; only NOT SET matches it. That reading requires Attrs.Complete —
// without the completeness assertion an attribute the map omits is unknown,
// not unset, and the rule is Unknown.
//
// Two expressions are always unevaluable here rather than guessed at: an
// unparseable expression, and a version comparison (node:osVersion or
// node:tsVersion with an ordering operator), whose server-side comparison
// function is not documented closely enough to reproduce. Both report
// Unknown with a reason, never a wrong verdict.
func EvaluatePosture(name string, rules []string, attrs Attrs) Outcome {
	outcome := Outcome{Posture: name, Rules: make([]RuleOutcome, 0, len(rules)), complete: attrs.Complete}
	for _, expression := range rules {
		outcome.Rules = append(outcome.Rules, evaluateRuleAgainstAttrs(expression, attrs))
	}
	return outcome
}

// versionAttributes order by a server-side comparison function that is not
// documented closely enough to reproduce locally, so ordering comparisons
// against them stay unevaluable.
var versionAttributes = map[string]bool{ //nolint:gochecknoglobals // a fixed, read-only vocabulary pair.
	"node:osVersion":     true,
	nodeVersionAttribute: true,
}

func evaluateRuleAgainstAttrs(expression string, attrs Attrs) RuleOutcome {
	trimmed := strings.TrimSpace(expression)
	parsed, ok := parseRule(trimmed)
	if !ok {
		return RuleOutcome{
			Expression: trimmed,
			State:      Unknown,
			Reason:     "unsupported posture expression: " + trimmed,
		}
	}
	outcome := RuleOutcome{Expression: trimmed, Attribute: parsed.attribute}
	if versionAttributes[parsed.attribute] && isOrderingOperator(parsed.operator) {
		outcome.State = Unknown
		outcome.Reason = fmt.Sprintf(
			"%s uses a version comparison, which is not evaluated locally", trimmed)
		return outcome
	}

	value, present := attrs.Map[parsed.attribute]
	if !present {
		outcome.State, outcome.Reason = unsetOutcome(parsed, attrs)
		outcome.MissingAttribute = outcome.State == Unknown
		return outcome
	}
	switch parsed.operator {
	case opIsSet:
		outcome.State, outcome.Reason = Satisfied, parsed.attribute+" is set"
		return outcome
	case opNotSet:
		outcome.State, outcome.Reason = Unsatisfied, parsed.attribute+" is set"
		return outcome
	}
	outcome.State, outcome.Reason = compareAgainstAttrs(parsed, value)
	return outcome
}

// unsetOutcome decides a rule whose attribute the map omits. With the
// completeness assertion the omission is an unset attribute and the server's
// semantics apply; without it the omission is a fact the caller never
// supplied, so no verdict may rest on it.
func unsetOutcome(parsed rule, attrs Attrs) (State, string) {
	if !attrs.Complete {
		return Unknown, fmt.Sprintf(
			"%s was not supplied and the attribute set is not asserted complete", parsed.attribute)
	}
	if parsed.operator == opNotSet {
		return Satisfied, parsed.attribute + " is unset"
	}
	return Unsatisfied, parsed.attribute + " is unset"
}

func isOrderingOperator(operator string) bool {
	switch operator {
	case opLess, opLessEqual, opGreater, opGreaterEqual:
		return true
	default:
		return false
	}
}

// compareAgainstAttrs applies the operator to a present value and renders
// the fact that decided it. It deliberately shares the normalization and
// comparison primitives with the Facts-based evaluator so the two paths
// cannot drift on what one value means.
func compareAgainstAttrs(parsed rule, value any) (State, string) {
	normalized := normalize(parsed.attribute, value)
	switch parsed.operator {
	case opBare:
		truthy, isBool := value.(bool)
		if !isBool {
			return Unknown, fmt.Sprintf(
				"%s is %s, which is not a boolean", parsed.attribute, renderFact(value))
		}
		return boolOutcome(truthy, fmt.Sprintf("%s is %s", parsed.attribute, renderFact(value)))
	case opEqual, opNotEqual:
		equal := valuesEqual(normalized, normalizeLiteral(parsed.attribute, parsed.literal))
		fact := fmt.Sprintf("%s is %s", parsed.attribute, renderFact(normalized))
		if !equal {
			fact = fmt.Sprintf("%s is %s, not %s",
				parsed.attribute, renderFact(normalized), renderFact(parsed.literal))
		}
		return boolOutcome(equal == (parsed.operator == opEqual), fact)
	case opIn, opNotIn:
		member := false
		for _, element := range parsed.list {
			if valuesEqual(normalized, normalizeLiteral(parsed.attribute, element)) {
				member = true
				break
			}
		}
		membership := "is not in"
		if member {
			membership = "is in"
		}
		fact := fmt.Sprintf("%s %s %s %s",
			parsed.attribute, renderFact(normalized), membership, renderList(parsed.list))
		return boolOutcome(member == (parsed.operator == opIn), fact)
	default:
		left, leftOK := toNumber(normalized)
		right, rightOK := toNumber(parsed.literal)
		if !leftOK || !rightOK {
			return Unknown, fmt.Sprintf(
				"%s is %s, which has no ordering", parsed.attribute, renderFact(value))
		}
		return orderedOutcome(parsed, compareFloat(left, right), normalized)
	}
}

func boolOutcome(satisfied bool, fact string) (State, string) {
	if satisfied {
		return Satisfied, fact
	}
	return Unsatisfied, fact
}

// orderedOutcome decides an ordering comparison and renders the relationship
// that actually holds between value and literal, so the fact reads true
// under either verdict: "custom:score 2 < 3" whether the rule wanted < or >=.
func orderedOutcome(parsed rule, ordering int, value any) (State, string) {
	relationship := "=="
	switch {
	case ordering < 0:
		relationship = "<"
	case ordering > 0:
		relationship = ">"
	}
	fact := fmt.Sprintf("%s %s %s %s",
		parsed.attribute, renderFact(value), relationship, renderFact(parsed.literal))
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
	return boolOutcome(satisfied, fact)
}

// renderFact formats a scalar for a fact statement: strings bare (KP),
// everything else the way render formats it. Fact text accompanies the
// expression it decided, which carries the literal's type, so the bare
// rendering stays unambiguous in context.
func renderFact(value any) string {
	if text, isText := value.(string); isText {
		return text
	}
	return render(value)
}

// renderList formats a membership list the way policies write one:
// ['KP', 'IR'].
func renderList(list []any) string {
	elements := make([]string, 0, len(list))
	for _, element := range list {
		if text, isText := element.(string); isText {
			elements = append(elements, "'"+text+"'")
			continue
		}
		elements = append(elements, renderFact(element))
	}
	return "[" + strings.Join(elements, ", ") + "]"
}
