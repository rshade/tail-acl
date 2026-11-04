package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/rshade/tsacl/internal/aclpolicy"
)

// autoApproverPolicy carries comments in each position the writer must
// preserve: on the document, trailing a member, leading a member, and inside
// the autoApprovers section itself.
const autoApproverPolicy = `{
	// Platform-owned policy. Edit with tsacl only.
	"tagOwners": {
		"tag:exit-node": ["autogroup:admin"], // approved by network-team
	},
	"groups": {
		"group:neteng": ["alice@example.com"],
	},
	"autoApprovers": {
		"routes": {
			// Lab subnet behind the dev router.
			"192.168.0.0/24": ["group:neteng"],
		},
		// Exit nodes auto-approved for tagged devices.
		"exitNode": ["tag:exit-node"],
	},
	"grants": [
		{"src": ["group:neteng"], "dst": ["tag:exit-node"], "ip": ["tcp:443"]},
	],
}
`

func TestAutoApproverAddThenRemoveReturnsOriginalBytes(t *testing.T) {
	t.Parallel()
	t.Run("new route key", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(t.TempDir(), "acl.hujson")
		writeTestPolicy(t, path, autoApproverPolicy)

		if _, err := runTSACL(t, path,
			"auto-approver", "add", "--route", "10.0.0.0/8", "--approver", "group:neteng"); err != nil {
			t.Fatal(err)
		}
		if _, err := runTSACL(t, path,
			"auto-approver", "remove", "--route", "10.0.0.0/8", "--approver", "group:neteng"); err != nil {
			t.Fatal(err)
		}
		if got := readPolicy(t, path); got != autoApproverPolicy {
			t.Errorf("add/remove round trip changed the file:\ngot:\n%s\nwant:\n%s", got, autoApproverPolicy)
		}
	})
	t.Run("exit-node list", func(t *testing.T) {
		t.Parallel()
		const base = `{
	"autoApprovers": {
		"exitNode": ["tag:exit-node"],
	},
}
`
		path := filepath.Join(t.TempDir(), "acl.hujson")
		writeTestPolicy(t, path, base)

		if _, err := runTSACL(t, path,
			"auto-approver", "add", "--exit-node", "--approver", "group:ops"); err != nil {
			t.Fatal(err)
		}
		if _, err := runTSACL(t, path,
			"auto-approver", "remove", "--exit-node", "--approver", "group:ops"); err != nil {
			t.Fatal(err)
		}
		if got := readPolicy(t, path); got != base {
			t.Errorf("add/remove round trip changed the file:\ngot:\n%s\nwant:\n%s", got, base)
		}
	})
}

// Emptying a member prunes the member but empties its block rather than
// deleting it — the rule grant remove and posture remove already apply to
// top-level keys — so a comment attached to the block survives the removal of
// its last entry.
func TestAutoApproverRemoveEmptiesButKeepsCommentedBlocks(t *testing.T) {
	t.Parallel()
	const base = `{
	"autoApprovers": {
		// Neteng owns every approval below; review quarterly.
		"routes": {
			"10.0.0.0/8": ["group:neteng"],
		},
		"exitNode": ["tag:exit-node"],
	},
}
`
	path := filepath.Join(t.TempDir(), "acl.hujson")
	writeTestPolicy(t, path, base)

	if _, err := runTSACL(t, path,
		"auto-approver", "remove", "--route", "10.0.0.0/8", "--approver", "group:neteng"); err != nil {
		t.Fatal(err)
	}
	if _, err := runTSACL(t, path,
		"auto-approver", "remove", "--exit-node", "--approver", "tag:exit-node"); err != nil {
		t.Fatal(err)
	}
	output := readPolicy(t, path)
	for _, pruned := range []string{"10.0.0.0/8", "exitNode"} {
		if strings.Contains(output, pruned) {
			t.Errorf("emptied member %q was not pruned:\n%s", pruned, output)
		}
	}
	if !strings.Contains(output, "// Neteng owns every approval below; review quarterly.") {
		t.Errorf("block comment was carried out with the last entry:\n%s", output)
	}
	if !strings.Contains(output, "autoApprovers") {
		t.Errorf("autoApprovers block was deleted instead of emptied:\n%s", output)
	}
	if _, err := aclpolicy.Load(path); err != nil {
		t.Errorf("edited policy no longer loads: %v\n%s", err, output)
	}
}

func TestAutoApproverAddIsIdempotent(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.hujson")
	writeTestPolicy(t, path, autoApproverPolicy)
	command := []string{"auto-approver", "add", "--route", "10.0.0.0/8", "--approver", "group:neteng"}

	if _, err := runTSACL(t, path, command...); err != nil {
		t.Fatal(err)
	}
	first := readPolicy(t, path)

	stdout, err := runTSACL(t, path, command...)
	if err != nil {
		t.Fatal(err)
	}
	if status := decodeStatus(t, stdout); status != statusNoChanges {
		t.Errorf("second add status = %q, want %q", status, statusNoChanges)
	}
	if second := readPolicy(t, path); second != first {
		t.Errorf("second add changed the file:\nfirst:\n%s\nsecond:\n%s", first, second)
	}
	policy, loadErr := aclpolicy.Load(path)
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	if got := policy.AutoApprovers.Routes["10.0.0.0/8"]; !slices.Equal(got, []string{"group:neteng"}) {
		t.Errorf("routes[10.0.0.0/8] = %v, want exactly one entry", got)
	}
}

func TestAutoApproverAddMergesIntoExistingRouteAndCanonicalizes(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.hujson")
	writeTestPolicy(t, path, autoApproverPolicy)

	// 192.168.0.9/24 masks to the existing 192.168.0.0/24 key, so the approver
	// must merge into that list rather than fork a second key.
	if _, err := runTSACL(t, path,
		"auto-approver", "add", "--route", "192.168.0.9/24", "--approver", "tag:router"); err != nil {
		t.Fatal(err)
	}
	policy, loadErr := aclpolicy.Load(path)
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	routes := policy.AutoApprovers.Routes
	if len(routes) != 1 {
		t.Fatalf("routes = %v, want the single masked key", routes)
	}
	if got := routes["192.168.0.0/24"]; !slices.Equal(got, []string{"group:neteng", "tag:router"}) {
		t.Errorf("routes[192.168.0.0/24] = %v, want merged list", got)
	}
}

func TestAutoApproverRemovePrunesEmptyRouteKey(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.hujson")
	writeTestPolicy(t, path, autoApproverPolicy)

	stdout, err := runTSACL(t, path,
		"auto-approver", "remove", "--route", "192.168.0.0/24", "--approver", "group:neteng")
	if err != nil {
		t.Fatal(err)
	}
	if status := decodeStatus(t, stdout); status != statusOK {
		t.Errorf("status = %q, want %q", status, statusOK)
	}
	output := readPolicy(t, path)
	if strings.Contains(output, "192.168.0.0/24") {
		t.Errorf("emptied route key was not pruned:\n%s", output)
	}
	if !strings.Contains(output, `"routes"`) {
		t.Errorf("routes block was deleted instead of emptied:\n%s", output)
	}
	// The exitNode sibling — member and comment — must survive the prune.
	assertCommentsOn(t, path,
		[]string{"Exit nodes auto-approved for tagged devices."}, "autoApprovers", "exitNode")
	policy, loadErr := aclpolicy.Load(path)
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	if !slices.Equal(policy.AutoApprovers.ExitNode, []string{"tag:exit-node"}) {
		t.Errorf("exitNode = %v, want preserved", policy.AutoApprovers.ExitNode)
	}
}

func TestAutoApproverRemoveIsIdempotent(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.hujson")
	writeTestPolicy(t, path, autoApproverPolicy)

	stdout, err := runTSACL(t, path,
		"auto-approver", "remove", "--route", "192.168.0.0/24", "--approver", "group:ghost")
	if err != nil {
		t.Fatal(err)
	}
	if status := decodeStatus(t, stdout); status != statusNoChanges {
		t.Errorf("status = %q, want %q", status, statusNoChanges)
	}
	if got := readPolicy(t, path); got != autoApproverPolicy {
		t.Errorf("removing an absent approver changed the file:\n%s", got)
	}
}

func TestAutoApproverCommentAuthoring(t *testing.T) {
	t.Parallel()
	const comment = "Lab routers redeploy weekly; see issue #122"
	t.Run("route member", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(t.TempDir(), "acl.hujson")
		writeTestPolicy(t, path, autoApproverPolicy)
		command := []string{"auto-approver", "add",
			"--route", "10.0.0.0/8", "--approver", "group:neteng", "--comment", comment}

		if _, err := runTSACL(t, path, command...); err != nil {
			t.Fatal(err)
		}
		assertCommentsOn(t, path, []string{comment}, "autoApprovers", "routes", "10.0.0.0/8")

		stdout, err := runTSACL(t, path, command...)
		if err != nil {
			t.Fatal(err)
		}
		if status := decodeStatus(t, stdout); status != statusNoChanges {
			t.Errorf("repeat status = %q, want %q", status, statusNoChanges)
		}
		if count := strings.Count(readPolicy(t, path), "// "+comment); count != 1 {
			t.Errorf("comment appears %d times, want 1", count)
		}
	})
	t.Run("exit-node member", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(t.TempDir(), "acl.hujson")
		writeTestPolicy(t, path, autoApproverPolicy)

		if _, err := runTSACL(t, path,
			"auto-approver", "add", "--exit-node", "--approver", "group:ops",
			"--comment", "Ops can approve exits too"); err != nil {
			t.Fatal(err)
		}
		assertCommentsOn(t, path,
			[]string{"Exit nodes auto-approved for tagged devices.", "Ops can approve exits too"},
			"autoApprovers", "exitNode")
	})
	t.Run("overwrite replaces the entry's comments", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(t.TempDir(), "acl.hujson")
		writeTestPolicy(t, path, autoApproverPolicy)

		stdout, err := runTSACL(t, path,
			"auto-approver", "add", "--exit-node", "--approver", "group:ops",
			"--comment", "Now the only note", "--overwrite-comment")
		if err != nil {
			t.Fatal(err)
		}
		if status := decodeStatus(t, stdout); status != statusOK {
			t.Errorf("status = %q, want %q", status, statusOK)
		}
		assertCommentsOn(t, path, []string{"Now the only note"}, "autoApprovers", "exitNode")
	})
}

// TestAutoApproverAddCommentOnlyEditIsNotReportedAsAnAddition covers the
// repeat-with-a-new-comment path: an approver the list already carries produces
// no edit operation, so the comment is the entire change. The message must say
// so rather than claim an addition the file does not contain — the distinction
// commentExistingOwner draws for "tag-owner add".
func TestAutoApproverAddCommentOnlyEditIsNotReportedAsAnAddition(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.hujson")
	writeTestPolicy(t, path, autoApproverPolicy)

	stdout, err := runTSACL(t, path,
		"auto-approver", "add", "--route", "192.168.0.0/24", "--approver", "group:neteng",
		"--comment", "Documented after the fact")
	if err != nil {
		t.Fatal(err)
	}
	var res result
	if err = json.Unmarshal([]byte(stdout), &res); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\n%s", err, stdout)
	}
	if res.Status != statusOK {
		t.Errorf("status = %q, want %q", res.Status, statusOK)
	}
	if strings.Contains(res.Message, "added approvers") {
		t.Errorf("Message = %q, want a comment-only edit not reported as an addition", res.Message)
	}
	policy, loadErr := aclpolicy.Load(path)
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	if got := policy.AutoApprovers.Routes["192.168.0.0/24"]; !slices.Equal(got, []string{"group:neteng"}) {
		t.Errorf("routes[192.168.0.0/24] = %v, want the list unchanged", got)
	}
	assertCommentsOn(t, path,
		[]string{"Lab subnet behind the dev router.", "Documented after the fact"},
		"autoApprovers", "routes", "192.168.0.0/24")
}

// nonMaskedRoutePolicy spells the routes key unmasked, the way a hand-authored
// policy can. NormalizeAutoApproverRoute masks the operator's --route argument,
// so a string lookup misses this key entirely.
const nonMaskedRoutePolicy = `{
	"groups": {
		"group:neteng": ["alice@example.com"],
		"group:ops": ["bob@example.com"],
	},
	"autoApprovers": {
		"routes": {
			"10.0.0.1/8": ["group:neteng"],
		},
	},
}
`

// TestAutoApproverResolvesNonMaskedRouteKey covers the key a string lookup
// cannot find. Both halves are silent wrong answers: add forked a second
// "10.0.0.0/8" beside the entry the operator can see, and remove reported
// "not present" for an approver plainly in the file.
func TestAutoApproverResolvesNonMaskedRouteKey(t *testing.T) {
	t.Parallel()
	t.Run("add merges into the file's spelling", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(t.TempDir(), "acl.hujson")
		writeTestPolicy(t, path, nonMaskedRoutePolicy)

		if _, err := runTSACL(t, path,
			"auto-approver", "add", "--route", "10.0.0.0/8", "--approver", "group:ops"); err != nil {
			t.Fatal(err)
		}
		policy, loadErr := aclpolicy.Load(path)
		if loadErr != nil {
			t.Fatal(loadErr)
		}
		routes := policy.AutoApprovers.Routes
		if len(routes) != 1 {
			t.Fatalf("routes = %v, want the single key the file already spelled", routes)
		}
		if got := routes["10.0.0.1/8"]; !slices.Equal(got, []string{"group:neteng", "group:ops"}) {
			t.Errorf("routes[10.0.0.1/8] = %v, want the approver merged into the existing list", got)
		}
	})
	t.Run("remove sees the approvers that key carries", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(t.TempDir(), "acl.hujson")
		writeTestPolicy(t, path, nonMaskedRoutePolicy)

		stdout, err := runTSACL(t, path,
			"auto-approver", "remove", "--route", "10.0.0.0/8", "--approver", "group:neteng")
		if err != nil {
			t.Fatal(err)
		}
		if status := decodeStatus(t, stdout); status != statusOK {
			t.Errorf("status = %q, want %q", status, statusOK)
		}
		if got := readPolicy(t, path); strings.Contains(got, "10.0.0.1/8") {
			t.Errorf("emptied route key was not pruned:\n%s", got)
		}
	})
	t.Run("comment attaches to the file's spelling", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(t.TempDir(), "acl.hujson")
		writeTestPolicy(t, path, nonMaskedRoutePolicy)

		if _, err := runTSACL(t, path,
			"auto-approver", "add", "--route", "10.0.0.0/8", "--approver", "group:ops",
			"--comment", "Legacy unmasked key"); err != nil {
			t.Fatal(err)
		}
		assertCommentsOn(t, path, []string{"Legacy unmasked key"},
			"autoApprovers", "routes", "10.0.0.1/8")
	})
}

func TestAutoApproverEditsPreserveCommentsAndKeyOrder(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.hujson")
	writeTestPolicy(t, path, autoApproverPolicy)

	if _, err := runTSACL(t, path,
		"auto-approver", "add", "--route", "10.0.0.0/8", "--approver", "group:neteng"); err != nil {
		t.Fatal(err)
	}
	output := readPolicy(t, path)
	for _, preserved := range []string{
		"// Platform-owned policy. Edit with tsacl only.",
		"// approved by network-team",
		"// Lab subnet behind the dev router.",
		"// Exit nodes auto-approved for tagged devices.",
	} {
		if !strings.Contains(output, preserved) {
			t.Errorf("edited policy lost %q:\n%s", preserved, output)
		}
	}
	assertPolicyKeyOrder(t, output, "tagOwners", "groups", "autoApprovers", "grants")
	if _, err := aclpolicy.Load(path); err != nil {
		t.Errorf("edited policy no longer loads: %v\n%s", err, output)
	}
}

func TestAutoApproverUsageErrorsLeaveFileUntouched(t *testing.T) {
	t.Parallel()
	testCases := map[string][]string{
		"route and exit-node together": {
			"auto-approver",
			"add",
			"--route",
			"10.0.0.0/8",
			"--exit-node",
			"--approver",
			"group:ops",
		},
		"neither section":       {"auto-approver", "add", "--approver", "group:ops"},
		"route is not a CIDR":   {"auto-approver", "add", "--route", "web", "--approver", "group:ops"},
		"no approver on add":    {"auto-approver", "add", "--route", "10.0.0.0/8"},
		"no approver on remove": {"auto-approver", "remove", "--route", "10.0.0.0/8"},
		"comment on remove": {
			"auto-approver",
			"remove",
			"--route",
			"10.0.0.0/8",
			"--approver",
			"group:ops",
			"--comment",
			"no",
		},
		"overwrite without comment": {
			"auto-approver",
			"add",
			"--route",
			"10.0.0.0/8",
			"--approver",
			"group:ops",
			"--overwrite-comment",
		},
	}
	for name, command := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "acl.hujson")
			writeTestPolicy(t, path, autoApproverPolicy)

			_, err := runTSACL(t, path, command...)
			if code := exitCode(err); code != exitUsage {
				t.Errorf("exit code = %d, want %d (error %v)", code, exitUsage, err)
			}
			if got := readPolicy(t, path); got != autoApproverPolicy {
				t.Errorf("rejected edit changed the file:\n%s", got)
			}
		})
	}
}

// A bare parent prints its verb list and exits 0, like the other grouping
// commands; an unknown verb is a usage error.
func TestAutoApproverParentCommand(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.hujson")
	writeTestPolicy(t, path, autoApproverPolicy)

	if _, err := runTSACL(t, path, "auto-approver"); err != nil {
		t.Errorf("bare auto-approver: %v", err)
	}
	if _, err := runTSACL(t, path, "auto-approver", "bogus"); exitCode(err) != exitUsage {
		t.Errorf("unknown verb exit = %d, want %d (error %v)", exitCode(err), exitUsage, err)
	}
}

// TestAutoApproverRemoveRejectsInvalidRoute covers the remove path's own
// validation, which resolves the target before touching the file.
func TestAutoApproverRemoveRejectsInvalidRoute(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.hujson")
	original := []byte("{\n\t// untouched\n}\n")
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := runTSACL(t, path, "auto-approver", "remove", "--route", "10.0.0.0/33", "--approver", "group:ops")
	if code := exitCode(err); code != exitUsage {
		t.Fatalf("exit code = %d, want %d (error %v)", code, exitUsage, err)
	}
	after, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(after) != string(original) {
		t.Errorf("rejected edit changed file:\n%s", after)
	}
}
