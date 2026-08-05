package aclpolicy

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	tailscale "tailscale.com/client/tailscale/v2"
)

// TestExpectation is the canonical spelling used by policy-test assertion IDs.
type TestExpectation string

const (
	TestAccept TestExpectation = "accept"
	TestDeny   TestExpectation = "deny"

	// testField* are ACLTest JSON member names, and their authority is the struct
	// tags upstream rather than any vocabulary declared here. They are spelled
	// out because the resemblance is a coincidence, not an invariant: an
	// assertion ID reports accept for an entry stored under the legacy allow
	// member, and allow's match with AccessAllow is a collision between the
	// reachability verdicts and a policy key. Deriving either would let a rename
	// elsewhere retarget an edit at a member no policy has.
	testFieldAccept = "accept"
	testFieldAllow  = "allow"
	testFieldDeny   = "deny"
)

// TestEdit describes the syntax-tree changes needed for an assertion edit.
// Callers apply Operations with WritePatch after loading the typed policy.
type TestEdit struct {
	TestIndex    int
	AssertionIDs []string
	Operations   []PatchOperation
}

// Changed reports whether the edit has any file operations to apply.
func (e TestEdit) Changed() bool { return len(e.Operations) != 0 }

// TestAssertionKey returns the semantic identity of one independent policy
// assertion. Test lists are disjunctive, so the containing ACLTest is not part
// of the key. Source and destination comparison is byte-exact after trimming.
func TestAssertionKey(source string, expectation TestExpectation, destination string) string {
	encoded, _ := json.Marshal([3]string{
		strings.TrimSpace(source),
		string(expectation),
		strings.TrimSpace(destination),
	})
	return string(encoded)
}

// ValidateTestDestination applies the same host:port parser used by the local
// test runner, preventing authoring an assertion the next test run cannot read.
func ValidateTestDestination(destination string) error {
	_, err := parseTarget(destination)
	return err
}

// AddAssertion adds one assertion to policy and returns its patch plan. It is a
// convenience wrapper around AddAssertions for package callers authoring one
// assertion at a time.
func AddAssertion(
	policy *Policy,
	source string,
	expectation TestExpectation,
	destination string,
) (TestEdit, error) {
	switch expectation {
	case TestDeny:
		return AddAssertions(policy, source, []string{destination}, nil)
	case TestAccept:
		return AddAssertions(policy, source, nil, []string{destination})
	default:
		return TestEdit{}, fmt.Errorf("unknown test expectation %q", expectation)
	}
}

// AddAssertions adds every semantically absent assertion, merging into the
// first plain entry for source. An entry carrying srcPostureAttrs is never a
// merge target because the local evaluator cannot run it. Existing assertions
// are returned in AssertionIDs too, making a no_changes result useful to CI.
func AddAssertions(policy *Policy, source string, deny, accept []string) (TestEdit, error) {
	source, deny, accept, err := validateTestEditInput(source, deny, accept)
	if err != nil {
		return TestEdit{}, err
	}

	edit := TestEdit{TestIndex: -1}
	seen := make(map[string]struct{}, len(deny)+len(accept))
	for _, assertion := range []struct {
		expectation  TestExpectation
		destinations []string
	}{
		{TestDeny, deny},
		{TestAccept, accept},
	} {
		for _, destination := range assertion.destinations {
			key := TestAssertionKey(source, assertion.expectation, destination)
			if _, duplicate := seen[key]; duplicate {
				continue
			}
			seen[key] = struct{}{}

			index, assertionID, operation := addOneAssertion(
				policy, source, assertion.expectation, destination,
			)
			if edit.TestIndex < 0 {
				edit.TestIndex = index
			}
			edit.AssertionIDs = append(edit.AssertionIDs, assertionID)
			if operation != nil {
				edit.Operations = append(edit.Operations, *operation)
			}
		}
	}
	return edit, nil
}

// RemoveAssertion removes every occurrence of one semantic assertion. Removing
// duplicates together makes the operation idempotent even on hand-edited input.
func RemoveAssertion(
	policy *Policy,
	source string,
	expectation TestExpectation,
	destination string,
) (TestEdit, error) {
	switch expectation {
	case TestDeny:
		return RemoveAssertions(policy, source, []string{destination}, nil)
	case TestAccept:
		return RemoveAssertions(policy, source, nil, []string{destination})
	default:
		return TestEdit{}, fmt.Errorf("unknown test expectation %q", expectation)
	}
}

// RemoveAssertions removes matching assertions, their now-empty assertion
// keys, and entries that carry no assertions afterward. Operations are emitted
// from the end of tests toward the beginning so array indexes remain valid.
func RemoveAssertions(policy *Policy, source string, deny, accept []string) (TestEdit, error) {
	source, deny, accept, err := validateTestEditInput(source, deny, accept)
	if err != nil {
		return TestEdit{}, err
	}
	requested := map[TestExpectation]map[string]struct{}{
		TestDeny:   destinationSet(source, TestDeny, deny),
		TestAccept: destinationSet(source, TestAccept, accept),
	}

	edit, removals := collectTestRemovals(policy, source, requested)
	for _, removal := range slices.Backward(removals) {
		edit.Operations = append(edit.Operations, applyTestRemoval(policy, removal)...)
	}
	return edit, nil
}

type testFieldRemoval struct {
	name    string
	indexes []int
}

type testEntryRemoval struct {
	index  int
	fields []testFieldRemoval
}

func collectTestRemovals(
	policy *Policy,
	source string,
	requested map[TestExpectation]map[string]struct{},
) (TestEdit, []testEntryRemoval) {
	edit := TestEdit{TestIndex: -1}
	var removals []testEntryRemoval
	for testIndex, test := range policy.Tests {
		if !editableTestMatches(test, source) {
			continue
		}
		if edit.TestIndex < 0 {
			edit.TestIndex = testIndex
		}

		entry := testEntryRemoval{index: testIndex}
		acceptField, acceptValues := effectiveAcceptField(test)
		collectFieldRemoval(
			&edit, &entry, source, TestAccept, acceptField, acceptValues, requested[TestAccept],
		)
		collectFieldRemoval(
			&edit, &entry, source, TestDeny, testFieldDeny, test.Deny, requested[TestDeny],
		)
		if len(entry.fields) != 0 {
			removals = append(removals, entry)
		}
	}
	return edit, removals
}

func collectFieldRemoval(
	edit *TestEdit,
	entry *testEntryRemoval,
	source string,
	expectation TestExpectation,
	fieldName string,
	values []string,
	requested map[string]struct{},
) {
	var indexes []int
	for assertionIndex, destination := range values {
		key := TestAssertionKey(source, expectation, destination)
		if _, remove := requested[key]; !remove {
			continue
		}
		indexes = append(indexes, assertionIndex)
		edit.AssertionIDs = append(edit.AssertionIDs,
			assertionID(entry.index, expectation, assertionIndex))
	}
	if len(indexes) != 0 {
		entry.fields = append(entry.fields, testFieldRemoval{fieldName, indexes})
	}
}

func applyTestRemoval(policy *Policy, removal testEntryRemoval) []PatchOperation {
	test := &policy.Tests[removal.index]
	for _, field := range removal.fields {
		setTestField(test, field.name, removeStringIndexes(testField(test, field.name), field.indexes))
	}
	if !testHasAssertions(*test) {
		policy.Tests = slices.Delete(policy.Tests, removal.index, removal.index+1)
		return []PatchOperation{PatchRemove("tests", strconv.Itoa(removal.index))}
	}

	var operations []PatchOperation
	for _, field := range removal.fields {
		if len(testField(test, field.name)) == 0 {
			operations = append(operations,
				PatchRemove("tests", strconv.Itoa(removal.index), field.name))
			continue
		}
		for _, assertionIndex := range slices.Backward(field.indexes) {
			operations = append(operations, PatchRemove(
				"tests", strconv.Itoa(removal.index), field.name, strconv.Itoa(assertionIndex),
			))
		}
	}
	return operations
}

func testField(test *tailscale.ACLTest, name string) []string {
	switch name {
	case testFieldAccept:
		return test.Accept
	case testFieldAllow:
		return test.Allow
	case testFieldDeny:
		return test.Deny
	default:
		return nil
	}
}

func setTestField(test *tailscale.ACLTest, name string, values []string) {
	switch name {
	case testFieldAccept:
		test.Accept = values
	case testFieldAllow:
		test.Allow = values
	case testFieldDeny:
		test.Deny = values
	}
}

func validateTestEditInput(source string, deny, accept []string) (string, []string, []string, error) {
	source = strings.TrimSpace(source)
	if source == "" {
		return "", nil, nil, errors.New("test source must not be empty")
	}
	if len(deny) == 0 && len(accept) == 0 {
		return "", nil, nil, errors.New("at least one deny or accept assertion is required")
	}
	trimAndValidate := func(values []string) ([]string, error) {
		trimmed := make([]string, len(values))
		for i, value := range values {
			value = strings.TrimSpace(value)
			if err := ValidateTestDestination(value); err != nil {
				return nil, err
			}
			trimmed[i] = value
		}
		return trimmed, nil
	}
	deny, err := trimAndValidate(deny)
	if err != nil {
		return "", nil, nil, err
	}
	accept, err = trimAndValidate(accept)
	if err != nil {
		return "", nil, nil, err
	}
	return source, deny, accept, nil
}

func addOneAssertion(
	policy *Policy,
	source string,
	expectation TestExpectation,
	destination string,
) (int, string, *PatchOperation) {
	target := -1
	for testIndex := range policy.Tests {
		test := policy.Tests[testIndex]
		if !editableTestMatches(test, source) {
			continue
		}
		if target < 0 {
			target = testIndex
		}
		_, values := assertionValues(test, expectation)
		for assertionIndex, existing := range values {
			if TestAssertionKey(source, expectation, existing) ==
				TestAssertionKey(source, expectation, destination) {
				return testIndex, assertionID(testIndex, expectation, assertionIndex), nil
			}
		}
	}

	if target < 0 {
		test := tailscale.ACLTest{Source: source}
		if expectation == TestDeny {
			test.Deny = []string{destination}
		} else {
			test.Accept = []string{destination}
		}
		testsPresent := policy.Tests != nil
		policy.Tests = append(policy.Tests, test)
		target = len(policy.Tests) - 1
		// Snapshot the new entry. AddAssertions may mutate policy.Tests again
		// before WritePatch marshals this operation (for example, two --deny
		// flags against a policy with no tests key). Keeping the live slice here
		// would let the first patch value observe the later append and then the
		// second operation would append that assertion a second time.
		operation := PatchAdd([]tailscale.ACLTest{test}, "tests")
		if testsPresent {
			operation = PatchAdd(test, "tests", "-")
		}
		return target, assertionID(target, expectation, 0), &operation
	}

	test := &policy.Tests[target]
	field, values := assertionValues(*test, expectation)
	fieldPresent := values != nil
	values = append(values, destination)
	setTestField(test, field, values)
	operation := PatchAdd(values, "tests", strconv.Itoa(target), field)
	if fieldPresent {
		operation = PatchAdd(destination, "tests", strconv.Itoa(target), field, "-")
	}
	return target, assertionID(target, expectation, len(values)-1), &operation
}

func editableTestMatches(test tailscale.ACLTest, source string) bool {
	// Length, not presence: EvaluateTests refuses an entry only when it carries
	// at least one posture attribute, so an entry spelling an empty
	// srcPostureAttrs object still runs and must stay editable. Gating on
	// presence would leave its assertions unremovable while the runner reports
	// them, and would fork a duplicate entry on the next add.
	if len(test.SrcPostureAttrs) != 0 {
		return false
	}
	normalized := test.Source
	if normalized == "" {
		normalized = test.User
	}
	return strings.TrimSpace(normalized) == source
}

func assertionValues(test tailscale.ACLTest, expectation TestExpectation) (string, []string) {
	if expectation == TestDeny {
		return testFieldDeny, test.Deny
	}
	return effectiveAcceptField(test)
}

// effectiveAcceptField names the accept-side member the local runner actually
// reads, so an edit lands where the next test run will look.
//
// The selection must track normalizeTest exactly. That function rejects an entry
// whose accept *and* allow are both non-empty, and otherwise reads accept when
// it is non-empty and falls back to allow. Choosing by presence rather than by
// length diverges on an entry carrying an explicitly empty accept beside a
// populated legacy allow: appending to accept there populates both members and
// makes the whole policy unrunnable, and a removal aimed at accept silently
// misses the assertion the runner is evaluating.
//
// An empty allow is still matched by name so an entry that spells the legacy key
// keeps that spelling rather than growing a second one.
func effectiveAcceptField(test tailscale.ACLTest) (string, []string) {
	if len(test.Accept) == 0 && test.Allow != nil {
		return testFieldAllow, test.Allow
	}
	return testFieldAccept, test.Accept
}

func assertionID(testIndex int, expectation TestExpectation, assertionIndex int) string {
	return fmt.Sprintf("tests[%d].%s[%d]", testIndex, expectation, assertionIndex)
}

func destinationSet(
	source string,
	expectation TestExpectation,
	destinations []string,
) map[string]struct{} {
	set := make(map[string]struct{}, len(destinations))
	for _, destination := range destinations {
		set[TestAssertionKey(source, expectation, destination)] = struct{}{}
	}
	return set
}

func removeStringIndexes(values []string, indexes []int) []string {
	for _, index := range slices.Backward(indexes) {
		values = slices.Delete(values, index, index+1)
	}
	return values
}

func testHasAssertions(test tailscale.ACLTest) bool {
	return len(test.Accept) != 0 || len(test.Allow) != 0 || len(test.Deny) != 0
}
