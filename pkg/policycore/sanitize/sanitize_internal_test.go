package sanitize

import (
	"bytes"
	"fmt"
	"testing"
)

// TestPseudonymNeverGrowsRetainedState guards the regression #207 identified:
// a long streaming export must not accumulate one map entry and one slice
// entry per distinct identity for the sanitizer's lifetime. Value does that
// deliberately (it powers Text); Pseudonym must not, no matter how many
// distinct values it sees.
func TestPseudonymNeverGrowsRetainedState(t *testing.T) {
	t.Parallel()

	sanitizer, err := New(Options{
		Level: Identity, Tool: "test", Random: bytes.NewReader(make([]byte, 32)),
	})
	if err != nil {
		t.Fatal(err)
	}

	for index := range 10_000 {
		sanitizer.Pseudonym("device", fmt.Sprintf("node-%d", index))
	}

	if len(sanitizer.byValue) != 0 || len(sanitizer.original) != 0 {
		t.Fatalf("Pseudonym() retained state after 10000 distinct values: byValue=%d original=%d; want 0, 0",
			len(sanitizer.byValue), len(sanitizer.original))
	}
}
