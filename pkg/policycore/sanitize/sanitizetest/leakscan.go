// Package sanitizetest provides assertions for output-sanitization tests.
package sanitizetest

import (
	"bytes"
)

// TestingT is the minimal test handle used by AssertNoIdentityLeaks.
type TestingT interface {
	Helper()
	Errorf(format string, args ...any)
}

// AssertNoIdentityLeaks reports every identity value found anywhere in
// rendered. Matching is ASCII case-insensitive and treats identities as plain
// substrings: unlike sanitize.Sanitizer.Text, a leaked value receives no token
// boundary exception once it reaches rendered output.
//
// identities must contain only non-empty real values from the fixture. An
// empty member is reported as a malformed test because every byte slice would
// otherwise contain it, and so is an empty set: a scan with nothing to look
// for passes vacuously, which is the likelier mistake when the caller built
// the set through an append chain.
//
// Values that differ only by ASCII case are one query, so only the first
// spelling of each is scanned. The report quotes the bytes actually found
// alongside the requested spelling, because those two need not match and a
// developer grepping the output for the requested one would otherwise find
// nothing.
func AssertNoIdentityLeaks(test TestingT, rendered []byte, identities []string) {
	test.Helper()

	if len(identities) == 0 {
		test.Errorf("identity set is empty; the scan would pass without checking anything")
		return
	}
	foldedOutput := foldASCII(rendered)
	seen := make(map[string]struct{}, len(identities))
	for index, identity := range identities {
		if identity == "" {
			test.Errorf("identity set contains an empty value at index %d", index)
			continue
		}
		foldedIdentity := foldASCII([]byte(identity))
		key := string(foldedIdentity)
		if _, duplicate := seen[key]; duplicate {
			continue
		}
		seen[key] = struct{}{}
		if offset := bytes.Index(foldedOutput, foldedIdentity); offset >= 0 {
			test.Errorf(
				"rendered output leaked identity %q at byte %d (found %q)",
				identity,
				offset,
				rendered[offset:offset+len(foldedIdentity)],
			)
		}
	}
}

func foldASCII(value []byte) []byte {
	folded := bytes.Clone(value)
	for index, character := range folded {
		if character >= 'A' && character <= 'Z' {
			folded[index] = character + ('a' - 'A')
		}
	}
	return folded
}
