package sanitizetest //nolint:testpackage // White-box tests exercise the assertion's error reporting.

import (
	"fmt"
	"strings"
	"testing"
)

func TestAssertNoIdentityLeaksScansTheWholeBufferCaseInsensitively(t *testing.T) {
	t.Parallel()

	recorder := &errorRecorder{}
	// EMBED-215 is planted with a token byte on both sides, so it is found only
	// because matching is a plain substring scan. A boundary-aware
	// reimplementation would miss it and pass every other assertion here, which
	// is exactly the regression this case exists to catch.
	AssertNoIdentityLeaks(
		recorder,
		[]byte(`{"safe":"prefix ROUTER.LeakScan.Example suffix","id":"node-215","x":"pEMBED-215q"}`),
		[]string{"router.leakscan.example", "NODE-215", "node-215", "EMBED-215", "missing.example", ""},
	)

	if len(recorder.messages) != 4 {
		t.Fatalf("reported errors = %d, want 4: %v", len(recorder.messages), recorder.messages)
	}
	for _, want := range []string{"router.leakscan.example", "NODE-215", "EMBED-215", "empty value"} {
		if !containsMessage(recorder.messages, want) {
			t.Errorf("errors do not mention %q: %v", want, recorder.messages)
		}
	}
	// The requested spelling and the bytes actually present differ here.
	if !containsMessage(recorder.messages, `found "node-215"`) {
		t.Errorf("error does not quote the bytes found: %v", recorder.messages)
	}
}

func TestAssertNoIdentityLeaksRejectsAnEmptyIdentitySet(t *testing.T) {
	t.Parallel()

	recorder := &errorRecorder{}
	AssertNoIdentityLeaks(recorder, []byte(`{"id":"node-215"}`), nil)

	if len(recorder.messages) != 1 || !containsMessage(recorder.messages, "identity set is empty") {
		t.Errorf("empty identity set was not reported as malformed: %v", recorder.messages)
	}
}

type errorRecorder struct {
	messages []string
}

func (*errorRecorder) Helper() {}

func (recorder *errorRecorder) Errorf(format string, args ...any) {
	recorder.messages = append(recorder.messages, fmt.Sprintf(format, args...))
}

func containsMessage(messages []string, fragment string) bool {
	for _, message := range messages {
		if strings.Contains(message, fragment) {
			return true
		}
	}
	return false
}
