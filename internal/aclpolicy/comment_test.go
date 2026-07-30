package aclpolicy_test

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	tailscale "tailscale.com/client/tailscale/v2"

	"github.com/rshade/tailscale-utils/tail-acl/internal/aclpolicy"
)

// commentFixture carries a comment in each position that decides attribution:
// one trailing a member on its own line (tag:web), one leading a member
// (hosts.legacy), and one array element with none.
const commentFixture = `{
	"tagOwners": {
		"tag:web": ["group:ops"], // web front ends
		"tag:db": ["autogroup:admin"],
	},
	"hosts": {
		// Legacy monitoring endpoint
		"legacy": "100.64.0.9",
	},
	"grants": [
		{"src": ["group:keep"], "dst": ["tag:db"], "ip": ["tcp:5432"]},
	],
}
`

func TestPatchCommentAttachesToArrayElementAndObjectMember(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.hujson")
	writeFile(t, path, commentFixture)

	grant := tailscale.Grant{Source: []string{"group:new"}, Destination: []string{"tag:web"}, IP: []string{"tcp:443"}}
	err := aclpolicy.WritePatch(path,
		aclpolicy.PatchAdd(grant, "grants", "-"),
		aclpolicy.PatchComment("New grant", "grants", "-"),
		aclpolicy.PatchAdd("100.64.0.20", "hosts", "web"),
		aclpolicy.PatchComment("Web host", "hosts", "web"),
	)
	if err != nil {
		t.Fatal(err)
	}

	assertLeadingComments(t, path, []string{"New grant"}, "grants", "-")
	assertLeadingComments(t, path, []string{"Web host"}, "hosts", "web")

	output := readFile(t, path)
	for _, want := range []string{"// New grant", "// Web host"} {
		if !strings.Contains(output, want) {
			t.Errorf("output missing %q:\n%s", want, output)
		}
	}
	if _, err = aclpolicy.Load(path); err != nil {
		t.Errorf("commented policy no longer loads: %v\n%s", err, output)
	}
}

// A comment authored onto an entry that already carries one must not displace
// it. hujson's own patch path would: injectLeadingComments truncates the slot
// before appending, so routing the comment through the patch document instead of
// annotating the tree afterwards silently deletes the operator's text.
func TestPatchCommentPreservesExistingLeadingComments(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.hujson")
	writeFile(t, path, commentFixture)

	err := aclpolicy.WritePatch(path,
		aclpolicy.PatchAdd("100.64.0.99", "hosts", "legacy"),
		aclpolicy.PatchComment("Now the canary", "hosts", "legacy"),
	)
	if err != nil {
		t.Fatal(err)
	}

	assertLeadingComments(t, path, []string{"Legacy monitoring endpoint", "Now the canary"}, "hosts", "legacy")
}

func TestPatchCommentIsIdempotent(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.hujson")
	writeFile(t, path, commentFixture)

	operations := []aclpolicy.PatchOperation{
		aclpolicy.PatchAdd("100.64.0.99", "hosts", "legacy"),
		aclpolicy.PatchComment("Now the canary", "hosts", "legacy"),
	}
	if err := aclpolicy.WritePatch(path, operations...); err != nil {
		t.Fatal(err)
	}
	first := readFile(t, path)
	if err := aclpolicy.WritePatch(path, operations...); err != nil {
		t.Fatal(err)
	}
	second := readFile(t, path)

	if first != second {
		t.Errorf("second write changed the file:\nfirst:\n%s\nsecond:\n%s", first, second)
	}
	if count := strings.Count(second, "// Now the canary"); count != 1 {
		t.Errorf("comment appears %d times, want 1:\n%s", count, second)
	}
}

// A comment on the line a member ends on belongs to that member, not the one
// after it. Counting it as the next member's would let a neighbour's note
// suppress an identical one here, and let an overwrite delete text describing a
// different entry.
func TestLeadingCommentsIgnorePreviousLineTrailingComment(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.hujson")
	writeFile(t, path, commentFixture)

	assertLeadingComments(t, path, nil, "tagOwners", "tag:db")
	assertLeadingComments(t, path, []string{"Legacy monitoring endpoint"}, "hosts", "legacy")

	// The neighbour's text is not a duplicate of tag:db's, so authoring it here
	// is a real change rather than a no-op.
	if err := aclpolicy.WritePatch(path, aclpolicy.PatchComment("web front ends", "tagOwners", "tag:db")); err != nil {
		t.Fatal(err)
	}
	assertLeadingComments(t, path, []string{"web front ends"}, "tagOwners", "tag:db")
	if count := strings.Count(readFile(t, path), "// web front ends"); count != 2 {
		t.Errorf("want the neighbour's comment kept alongside the new one:\n%s", readFile(t, path))
	}
}

func TestPatchCommentOverwriteReplacesOnlyItsOwnComments(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.hujson")
	writeFile(t, path, commentFixture)

	err := aclpolicy.WritePatch(path,
		aclpolicy.PatchCommentOverwrite("Now the canary", "hosts", "legacy"),
		aclpolicy.PatchCommentOverwrite("Database tags", "tagOwners", "tag:db"),
	)
	if err != nil {
		t.Fatal(err)
	}

	assertLeadingComments(t, path, []string{"Now the canary"}, "hosts", "legacy")
	assertLeadingComments(t, path, []string{"Database tags"}, "tagOwners", "tag:db")

	output := readFile(t, path)
	if strings.Contains(output, "Legacy monitoring endpoint") {
		t.Errorf("overwrite kept the replaced comment:\n%s", output)
	}
	// tag:web's trailing comment sits in tag:db's slot but is not tag:db's.
	if !strings.Contains(output, "// web front ends") {
		t.Errorf("overwrite consumed the preceding member's trailing comment:\n%s", output)
	}
}

func TestWritePatchAppliesCommentOnlyEdit(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.hujson")
	writeFile(t, path, commentFixture)

	// No RFC 6902 operation at all: the encoded patch is [], which hujson must
	// accept as an empty operation list.
	if err := aclpolicy.WritePatch(path, aclpolicy.PatchComment("Kept deliberately", "grants", "0")); err != nil {
		t.Fatal(err)
	}

	assertLeadingComments(t, path, []string{"Kept deliberately"}, "grants", "0")
	policy, err := aclpolicy.Load(path)
	if err != nil {
		t.Fatalf("comment-only edit broke the policy: %v", err)
	}
	if len(policy.Grants) != 1 {
		t.Errorf("grants = %d, want 1 unchanged", len(policy.Grants))
	}
}

func TestWritePatchFailsClosedOnUnresolvableCommentTarget(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.hujson")
	writeFile(t, path, commentFixture)
	before := readFile(t, path)

	err := aclpolicy.WritePatch(path, aclpolicy.PatchComment("nowhere", "hosts", "absent"))
	if err == nil {
		t.Fatal("commenting a missing node succeeded, want an error")
	}
	if !strings.Contains(err.Error(), "no node at") {
		t.Errorf("error = %v, want it to name the unresolved node", err)
	}
	if after := readFile(t, path); after != before {
		t.Errorf("failed edit rewrote the file:\n%s", after)
	}
}

func TestLeadingCommentsReportsNothingForAbsentNode(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.hujson")
	writeFile(t, path, commentFixture)

	assertLeadingComments(t, path, nil, "hosts", "absent")
	assertLeadingComments(t, path, nil, "postures", "posture:absent")
}

func TestValidateCommentText(t *testing.T) {
	t.Parallel()
	testCases := map[string]struct {
		text    string
		wantErr bool
	}{
		"plain":            {"Database access for application nodes", false},
		"punctuation":      {"owner: platform-team (see #59)", false},
		"leading space":    {"  padded", false},
		"empty":            {"", true},
		"whitespace only":  {"   \t", true},
		"newline":          {"first\nsecond", true},
		"carriage return":  {"first\rsecond", true},
		"trailing newline": {"trailing\n", true},
		"invalid utf-8":    {"bad \xff byte", true},
	}
	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			err := aclpolicy.ValidateCommentText(testCase.text)
			if gotErr := err != nil; gotErr != testCase.wantErr {
				t.Errorf("ValidateCommentText(%q) error = %v, want error %t", testCase.text, err, testCase.wantErr)
			}
		})
	}
}

func assertLeadingComments(t *testing.T, path string, want []string, segments ...string) {
	t.Helper()
	got, err := aclpolicy.LeadingComments(path, segments...)
	if err != nil {
		t.Fatalf("LeadingComments(%v): %v", segments, err)
	}
	if !slices.Equal(got, want) {
		t.Errorf("LeadingComments(%v) = %q, want %q\n%s", segments, got, want, readFile(t, path))
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
