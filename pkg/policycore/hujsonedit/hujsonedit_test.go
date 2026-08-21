package hujsonedit_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tailscale/hujson"

	"github.com/rshade/tailscale-utils/policycore/hujsonedit"
)

func writeTemp(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "doc.hujson")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("writing fixture: %v", err)
	}
	return path
}

func readAll(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	return string(b)
}

func TestWritePatchAddsToEmptyObject(t *testing.T) {
	t.Parallel()
	path := writeTemp(t, "{}\n")

	if err := hujsonedit.WritePatch(path, nil,
		hujsonedit.PatchAdd("bar", "foo")); err != nil {
		t.Fatalf("WritePatch: %v", err)
	}

	document, err := hujsonedit.ParseFile(path)
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}
	found := document.Find(hujsonedit.JSONPointer("foo"))
	if found == nil {
		t.Fatal(`"foo" not found after add`)
	}
	if got := found.Value.(hujson.Literal).String(); got != "bar" {
		t.Errorf(`"foo" = %s, want "bar"`, got)
	}
}

func TestWritePatchPreservesExistingComment(t *testing.T) {
	t.Parallel()
	path := writeTemp(t, `{
	// pinned for the migration
	"foo": "bar",
}
`)

	if err := hujsonedit.WritePatch(path, nil,
		hujsonedit.PatchAdd("baz", "quux")); err != nil {
		t.Fatalf("WritePatch: %v", err)
	}

	got := readAll(t, path)
	if want := "// pinned for the migration"; !strings.Contains(got, want) {
		t.Errorf("output = %q, want it to still contain %q", got, want)
	}
	if !strings.Contains(got, `"quux"`) {
		t.Errorf("output = %q, want the new key present", got)
	}
}

func TestPatchCommentAppendsNewLine(t *testing.T) {
	t.Parallel()
	path := writeTemp(t, `{"foo": "bar"}`+"\n")

	if err := hujsonedit.WritePatch(path, nil,
		hujsonedit.PatchComment("why foo exists", "foo")); err != nil {
		t.Fatalf("WritePatch: %v", err)
	}

	comments, err := hujsonedit.LeadingComments(path, nil, "foo")
	if err != nil {
		t.Fatalf("LeadingComments: %v", err)
	}
	if len(comments) != 1 || comments[0] != "why foo exists" {
		t.Errorf("LeadingComments = %v, want [\"why foo exists\"]", comments)
	}
}

func TestPatchCommentOverwriteReplacesLines(t *testing.T) {
	t.Parallel()
	path := writeTemp(t, `{
	// old note
	// second old note
	"foo": "bar",
}
`)

	if err := hujsonedit.WritePatch(path, nil,
		hujsonedit.PatchCommentOverwrite("new note", "foo")); err != nil {
		t.Fatalf("WritePatch: %v", err)
	}

	comments, err := hujsonedit.LeadingComments(path, nil, "foo")
	if err != nil {
		t.Fatalf("LeadingComments: %v", err)
	}
	if len(comments) != 1 || comments[0] != "new note" {
		t.Errorf("LeadingComments = %v, want [\"new note\"]", comments)
	}
}

func TestPatchCommentSkipsDuplicate(t *testing.T) {
	t.Parallel()
	path := writeTemp(t, `{
	// already here
	"foo": "bar",
}
`)

	if err := hujsonedit.WritePatch(path, nil,
		hujsonedit.PatchComment("already here", "foo")); err != nil {
		t.Fatalf("WritePatch: %v", err)
	}

	comments, err := hujsonedit.LeadingComments(path, nil, "foo")
	if err != nil {
		t.Fatalf("LeadingComments: %v", err)
	}
	if len(comments) != 1 {
		t.Errorf("LeadingComments = %v, want exactly one entry (no duplicate)", comments)
	}
}

func TestLeadingCommentsOnAbsentNodeIsNilNotError(t *testing.T) {
	t.Parallel()
	path := writeTemp(t, "{}\n")

	comments, err := hujsonedit.LeadingComments(path, nil, "missing")
	if err != nil {
		t.Fatalf("LeadingComments: %v", err)
	}
	if comments != nil {
		t.Errorf("LeadingComments = %v, want nil for an absent node", comments)
	}
}

func TestWritePatchResolveKeyIsInvokedForAliasedTopLevelKey(t *testing.T) {
	t.Parallel()
	// The document spells its top-level key "Foo" (legacy casing); the caller
	// authors operations against the canonical lowercase "foo" and supplies a
	// resolver that bridges the two, mirroring tail-acl's resolveTopLevelKey.
	path := writeTemp(t, `{"Foo": {}}`+"\n")

	invoked := false
	resolve := func(document hujson.Value, canonical string) string {
		invoked = true
		if canonical != "foo" {
			return canonical
		}
		if document.Find(hujsonedit.JSONPointer("Foo")) != nil {
			return "Foo"
		}
		return canonical
	}

	if err := hujsonedit.WritePatch(path, resolve,
		hujsonedit.PatchAdd("bar", "foo", "nested")); err != nil {
		t.Fatalf("WritePatch: %v", err)
	}
	if !invoked {
		t.Fatal("resolve was never called")
	}

	document, err := hujsonedit.ParseFile(path)
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}
	if found := document.Find(hujsonedit.JSONPointer("Foo", "nested")); found == nil {
		t.Fatal(`"Foo.nested" not found after add through the resolved alias`)
	}
}

func TestValidateCommentTextRejectsMultilineAndEmpty(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		text string
		ok   bool
	}{
		{"empty", "", false},
		{"whitespace only", "   ", false},
		{"newline", "one\ntwo", false},
		{"carriage return", "one\rtwo", false},
		{"valid", "a fine comment", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := hujsonedit.ValidateCommentText(tc.text)
			if (err == nil) != tc.ok {
				t.Errorf("ValidateCommentText(%q) error = %v, want ok=%v", tc.text, err, tc.ok)
			}
		})
	}
}

func TestWritePatchRejectsInvalidCommentAndPreservesFile(t *testing.T) {
	t.Parallel()
	originalContent := `{"foo": "bar"}` + "\n"
	path := writeTemp(t, originalContent)

	// Attempt to patch with an invalid comment containing a newline
	err := hujsonedit.WritePatch(path, nil,
		hujsonedit.PatchComment("note\n\"injected\": \"pwned\",", "foo"))
	if err == nil {
		t.Fatal("WritePatch should have returned an error for invalid comment text")
	}
	if !strings.Contains(err.Error(), "must not contain a carriage return or newline") {
		t.Errorf("WritePatch error = %v, want it to mention the newline validation", err)
	}

	// Verify the file was not corrupted and remains unchanged
	got := readAll(t, path)
	if got != originalContent {
		t.Errorf("file was modified despite patch failure\ngot:\n%s\nwant:\n%s", got, originalContent)
	}

	// Verify the injected "injected" field does not exist
	document, err := hujsonedit.ParseFile(path)
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}
	if injected := document.Find(hujsonedit.JSONPointer("injected")); injected != nil {
		t.Error("file contains the injected field despite patch rejection")
	}
}
