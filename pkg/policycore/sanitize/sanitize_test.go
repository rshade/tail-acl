package sanitize_test

import (
	"bytes"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rshade/tsacl/pkg/policycore/sanitize"
)

func TestParseLevel(t *testing.T) {
	t.Parallel()

	tests := []struct {
		value   string
		want    sanitize.Level
		wantErr bool
	}{
		{"", sanitize.Off, false},
		{"off", sanitize.Off, false},
		{"identity", sanitize.Identity, false},
		{"strict", sanitize.Strict, false},
		{"Identity", sanitize.Off, true},
		{" identity", sanitize.Off, true},
		{"unknown", sanitize.Off, true},
	}
	for _, test := range tests {
		t.Run(test.value, func(t *testing.T) {
			t.Parallel()
			got, err := sanitize.ParseLevel(test.value)
			if got != test.want || (err != nil) != test.wantErr {
				t.Fatalf("ParseLevel(%q) = (%q, %v), want (%q, error=%v)",
					test.value, got, err, test.want, test.wantErr)
			}
			if test.wantErr && !strings.Contains(err.Error(), "off, identity, or strict") {
				t.Errorf("error does not name valid levels: %v", err)
			}
		})
	}
}

func TestResolveEnvironmentPrecedence(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		env      string
		flag     string
		explicit bool
		want     sanitize.Resolution
	}{
		{"defaults", "", "off", false, sanitize.Resolution{Level: sanitize.Off}},
		{"flag", "", "strict", true, sanitize.Resolution{Level: sanitize.Strict}},
		{"environment", "identity", "off", false, sanitize.Resolution{
			Level: sanitize.Identity, EnvironmentActive: true,
		}},
		{"environment overrides", "identity", "off", true, sanitize.Resolution{
			Level: sanitize.Identity, EnvironmentActive: true, OverrodeFlag: true,
			FlagLevel: sanitize.Off,
		}},
		{"same explicit level", "identity", "identity", true, sanitize.Resolution{
			Level: sanitize.Identity, EnvironmentActive: true,
		}},
		{"off does not weaken", "off", "strict", true, sanitize.Resolution{Level: sanitize.Strict}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got, err := sanitize.Resolve(test.env, test.flag, test.explicit)
			if err != nil {
				t.Fatal(err)
			}
			if got != test.want {
				t.Errorf("Resolve() = %+v, want %+v", got, test.want)
			}
		})
	}
}

func TestSanitizerDeterministicAndScansText(t *testing.T) {
	t.Parallel()

	key := strings.Repeat("01", 32)
	first, err := sanitize.New(sanitize.Options{
		Level: sanitize.Identity, Tool: "test", Tailnet: "example.ts.net", KeyHex: key,
	})
	if err != nil {
		t.Fatal(err)
	}
	second, err := sanitize.New(sanitize.Options{
		Level: sanitize.Identity, Tool: "test", Tailnet: "example.ts.net", KeyHex: key,
	})
	if err != nil {
		t.Fatal(err)
	}

	want := first.Value("hostname", "router.example.ts.net")
	if got := first.Value("peer", "router.example.ts.net"); got != want {
		t.Errorf("same literal changed by kind: %q != %q", got, want)
	}
	if got := second.Value("hostname", "router.example.ts.net"); got != want {
		t.Errorf("same key changed placeholder: %q != %q", got, want)
	}
	address := first.Value("ip", "100.64.0.1")
	text := first.Text("router.example.ts.net via 100.64.0.1")
	if text != want+" via "+address {
		t.Errorf("Text() = %q", text)
	}
	if strings.Contains(text, "router.example.ts.net") || strings.Contains(text, "100.64.0.1") {
		t.Errorf("Text() retained identity: %q", text)
	}
	if !first.Metadata().Comparable(second.Metadata()) {
		t.Error("matching keyed metadata is not comparable")
	}
	malformed := *first.Metadata()
	malformed.KeyID = ""
	if malformed.Comparable(&malformed) {
		t.Error("metadata with no key identifier is comparable")
	}
}

func TestSanitizerScansShortDelimitedIdentitiesWithoutCorruptingLargerTokens(t *testing.T) {
	t.Parallel()

	output, err := sanitize.New(sanitize.Options{
		Level: sanitize.Identity, Tool: "test", Random: bytes.NewReader(make([]byte, 32)),
	})
	if err != nil {
		t.Fatal(err)
	}
	placeholder := output.Value("id", "0")
	got := output.Text("10 devices include id 0; code x0 stays")
	if got != "10 devices include id "+placeholder+"; code x0 stays" {
		t.Errorf("Text() = %q", got)
	}
}

func TestPseudonymDoesNotRegisterValueForText(t *testing.T) {
	t.Parallel()

	output, err := sanitize.New(sanitize.Options{
		Level: sanitize.Identity, Tool: "test", Random: bytes.NewReader(make([]byte, 32)),
	})
	if err != nil {
		t.Fatal(err)
	}

	const original = "203.0.113.10"
	placeholder := output.Pseudonym("ipv4", original)
	if placeholder == original {
		t.Fatal("Pseudonym() retained the original value")
	}
	if got := output.Pseudonym("ipv4", original); got != placeholder {
		t.Errorf("Pseudonym() = %q, want stable %q", got, placeholder)
	}
	if got := output.Text("peer " + original); got != "peer "+original {
		t.Errorf("Text() replaced an unregistered pseudonym input: %q", got)
	}
	if got := output.Value("ipv4", original); got != placeholder {
		t.Errorf("Value() = %q, want Pseudonym() result %q", got, placeholder)
	}
	if got := output.Text("peer " + original); got != "peer "+placeholder {
		t.Errorf("Text() did not replace registered input: %q", got)
	}
}

func TestEphemeralMetadataIsNotComparable(t *testing.T) {
	t.Parallel()

	left, err := sanitize.New(sanitize.Options{
		Level: sanitize.Identity, Tool: "test", Random: bytes.NewReader(make([]byte, 32)),
	})
	if err != nil {
		t.Fatal(err)
	}
	right, err := sanitize.New(sanitize.Options{
		Level: sanitize.Identity, Tool: "test", Random: bytes.NewReader(bytes.Repeat([]byte{1}, 32)),
	})
	if err != nil {
		t.Fatal(err)
	}
	if left.Metadata().Comparable(right.Metadata()) {
		t.Error("artifact-scoped metadata is comparable")
	}
	if left.Value("device", "node-1") == right.Value("device", "node-1") {
		t.Error("different ephemeral keys produced the same placeholder")
	}
}

func TestNewRejectsBadKeyAndRandomFailure(t *testing.T) {
	t.Parallel()

	if _, err := sanitize.New(sanitize.Options{
		Level: sanitize.Identity, Tool: "test", KeyHex: "weak",
	}); err == nil || !strings.Contains(err.Error(), sanitize.KeyEnv) {
		t.Fatalf("bad key error = %v", err)
	}
	if _, err := sanitize.New(sanitize.Options{
		Level: sanitize.Identity, Tool: "test", Random: errorReader{},
	}); err == nil || !strings.Contains(err.Error(), "ephemeral") {
		t.Fatalf("random error = %v", err)
	}
}

type errorReader struct{}

func (errorReader) Read([]byte) (int, error) { return 0, errors.New("entropy unavailable") }

func TestStrictQuantizesTimestamp(t *testing.T) {
	t.Parallel()

	value := time.Date(2026, time.August, 17, 17, 23, 11, 4, time.FixedZone("test", -5*60*60))
	identity, err := sanitize.New(sanitize.Options{
		Level: sanitize.Identity, Tool: "test", Random: bytes.NewReader(make([]byte, 32)),
	})
	if err != nil {
		t.Fatal(err)
	}
	strict, err := sanitize.New(sanitize.Options{
		Level: sanitize.Strict, Tool: "test", Random: bytes.NewReader(make([]byte, 32)),
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := identity.Time(value); !got.Equal(value) {
		t.Errorf("identity time = %s, want %s", got, value)
	}
	want := time.Date(2026, time.August, 17, 0, 0, 0, 0, time.UTC)
	if got := strict.Time(value); !got.Equal(want) {
		t.Errorf("strict time = %s, want %s", got, want)
	}
}

func TestTextCaseInsensitiveMatching(t *testing.T) {
	t.Parallel()

	key := strings.Repeat("01", 32)
	output, err := sanitize.New(sanitize.Options{
		Level: sanitize.Identity, Tool: "test", Tailnet: "example.ts.net", KeyHex: key,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Register a value in its original case.
	placeholder := output.Value("hostname", "Richards-MacBook-Pro")
	if placeholder == "" {
		t.Fatal("failed to register hostname")
	}

	// The Text() method should find and replace the value even when it appears
	// in different case in the input. This ensures normalized values (e.g.
	// lowercase hostnames in Evidence text) still get sanitized.
	text := output.Text("Connected via richards-macbook-pro in the evening")
	if !strings.Contains(text, placeholder) {
		t.Errorf("Text() failed to replace case-insensitive match: %q", text)
	}
	if strings.Contains(text, "Richards-MacBook-Pro") || strings.Contains(text, "richards-macbook-pro") {
		t.Errorf("Text() retained original identity in any case: %q", text)
	}
}

func TestTextPlaceholderNotCorruptedBySubsequentReplacements(t *testing.T) {
	t.Parallel()

	output, err := sanitize.New(sanitize.Options{
		Level: sanitize.Identity, Tool: "test", Random: bytes.NewReader(make([]byte, 32)),
	})
	if err != nil {
		t.Fatal(err)
	}

	// Register two values: a long one and a short one that happens to match
	// a substring of the long one's placeholder. Since placeholders are
	// lowercase base32 (alphabet a-z2-7), this can occur naturally.
	longValue := "super-long-hostname-value"
	shortValue := "ai"

	longPlaceholder := output.Value("hostname", longValue)
	shortPlaceholder := output.Value("id", shortValue)

	// The short placeholder might contain or be contained in characters from
	// the long placeholder. Apply Text() to a string that would expose the bug
	// if the old bare strings.ReplaceAll was used (which could partially
	// rewrite the long placeholder mid-token).
	text := output.Text("Found " + longValue + " and " + shortValue)

	// Both real values should be replaced with their placeholders.
	if !strings.Contains(text, longPlaceholder) {
		t.Errorf("long value not replaced: %q", text)
	}
	if !strings.Contains(text, shortPlaceholder) {
		t.Errorf("short value not replaced: %q", text)
	}

	// Neither original should appear.
	if strings.Contains(text, longValue) {
		t.Errorf("long original value retained: %q", text)
	}
	if strings.Contains(text, shortValue) {
		t.Errorf("short original value retained: %q", text)
	}

	// A registered value equal to a placeholder's kind prefix must not
	// corrupt that placeholder: Value("id", "laptop") yields "id-<digest>",
	// and registering "id" itself must not rewrite the "id" at the start of
	// that already-inserted placeholder ('-' is not a token byte, so the
	// boundary check alone does not protect it).
	prefixedPlaceholder := output.Value("id", "laptop")
	prefixPlaceholder := output.Value("device", "id")
	prefixedText := output.Text("laptop reports id")
	if !strings.Contains(prefixedText, prefixedPlaceholder) {
		t.Errorf("placeholder corrupted by kind-prefix value: %q, want it to contain %q",
			prefixedText, prefixedPlaceholder)
	}
	if !strings.Contains(prefixedText, prefixPlaceholder) {
		t.Errorf("kind-prefix value not replaced: %q, want it to contain %q",
			prefixedText, prefixPlaceholder)
	}
	if strings.Contains(prefixedText, "laptop") {
		t.Errorf("original value retained: %q", prefixedText)
	}
}

func TestUnhandledFields(t *testing.T) {
	t.Parallel()

	type guarded struct {
		Handled string
		Missing int
		private bool
	}
	_ = guarded{private: true}
	got := sanitize.UnhandledFields[guarded]("Handled")
	if !slices.Equal(got, []string{"Missing"}) {
		t.Errorf("UnhandledFields() = %v", got)
	}
}
