package posture

import (
	"os"
	"strings"
	"testing"
)

// fixtureCodes parses the country fixture the same way the package does, so
// the guard compares the package vocabulary against the file's codes, not
// against its own reading of them.
func fixtureCodes(t *testing.T) []string {
	t.Helper()

	data, err := os.ReadFile("testdata/ip_country_vocabulary.txt")
	if err != nil {
		t.Fatalf("reading the country fixture: %v", err)
	}
	var codes []string
	for line := range strings.Lines(string(data)) {
		code := strings.TrimSpace(line)
		if code == "" || strings.HasPrefix(code, "#") {
			continue
		}
		codes = append(codes, code)
	}
	return codes
}

// TestCountryVocabularyMatchesFixture is the AX convention 13 Tier-2
// provenance guard for the ip:country vocabulary. The fixture is the control
// plane's own accepted-country list, captured live on 2026-10-02 (see the
// file's header), and it is the source of truth: this guard fails if the
// package's vocabulary drifts from it in either direction. The expectations
// below are hand-written on purpose — a guard that read them from the
// package's own internals would prove nothing.
func TestCountryVocabularyMatchesFixture(t *testing.T) {
	t.Parallel()

	codes := fixtureCodes(t)
	const capturedCount = 250
	if len(codes) != capturedCount {
		t.Fatalf("fixture carries %d codes; the 2026-10-02 capture carried %d", len(codes), capturedCount)
	}

	set, ordered := ipCountryVocabulary()
	if len(set) != len(codes) {
		t.Errorf("package vocabulary has %d codes; the fixture has %d", len(set), len(codes))
	}
	if len(ordered) != len(codes) {
		t.Errorf("package ordered vocabulary has %d codes; the fixture has %d", len(ordered), len(codes))
	}
	for _, code := range codes {
		if !set[code] {
			t.Errorf("fixture code %q is missing from the package vocabulary", code)
		}
		const codeLength = 2
		if len(code) != codeLength || code != strings.ToUpper(code) {
			t.Errorf("fixture code %q is not a two-letter uppercase code", code)
		}
	}

	// XK (Kosovo) is in the server's list even though a stock ISO 3166-1 table
	// omits it. ZZ is absent: the Features/03 write-up claimed the server
	// accepts it, but that did not reproduce — its absence here was verified
	// against the live server on 2026-10-02 and is pinned so nobody
	// "corrects" the fixture from a stock table.
	if !set["XK"] {
		t.Error("XK is absent from the package vocabulary; the live server lists it")
	}
	if set["ZZ"] {
		t.Error("ZZ is present in the package vocabulary; the live server does not list it (verified 2026-10-02)")
	}
}

// TestKnownAttributeTable pins the editorial known-attribute table. Like the
// country guard, the expectations are hand-written: this is the Tier-2 guard
// for the attribute vocabulary Validate warns against. Adding a server
// attribute is a deliberate act — update this table and the test together.
func TestKnownAttributeTable(t *testing.T) {
	t.Parallel()

	want := map[string]attributeKind{
		"node:os":        attributeString,
		"node:osVersion": attributeVersion,
		"node:tsVersion": attributeVersion,
		"node:app":       attributeString,
		"ip:country":     attributeString,
	}
	if len(knownAttributes) != len(want) {
		t.Errorf("knownAttributes has %d entries; the pinned table has %d", len(knownAttributes), len(want))
	}
	for attribute, kind := range want {
		got, known := knownAttributes[attribute]
		if !known {
			t.Errorf("knownAttributes is missing %q", attribute)
			continue
		}
		if got != kind {
			t.Errorf("knownAttributes[%q] = %q; want %q", attribute, got, kind)
		}
	}
	for attribute := range knownAttributes {
		if _, pinned := want[attribute]; !pinned {
			t.Errorf("knownAttributes carries %q, which the pinned table does not list", attribute)
		}
	}
}
