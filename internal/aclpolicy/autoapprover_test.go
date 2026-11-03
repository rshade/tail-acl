package aclpolicy_test

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/rshade/tsacl/internal/aclpolicy"
)

func TestNormalizeAutoApproverRoute(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name  string
		input string
		want  string
	}{
		{"already masked", "10.0.0.0/8", "10.0.0.0/8"},
		{"host bits masked", "10.1.2.3/8", "10.0.0.0/8"},
		{"surrounding space", "  192.168.0.0/24  ", "192.168.0.0/24"},
		{"ipv6", "fd7a:115c:a1e0::1/48", "fd7a:115c:a1e0::/48"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := aclpolicy.NormalizeAutoApproverRoute(tc.input)
			if err != nil {
				t.Fatalf("NormalizeAutoApproverRoute(%q): %v", tc.input, err)
			}
			if got != tc.want {
				t.Errorf("NormalizeAutoApproverRoute(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
	for _, input := range []string{"", "   ", "10.0.0.0", "10.0.0.0/33", "not-a-route", "web"} {
		t.Run("rejects "+input, func(t *testing.T) {
			t.Parallel()
			if _, err := aclpolicy.NormalizeAutoApproverRoute(input); err == nil {
				t.Errorf("NormalizeAutoApproverRoute(%q) accepted, want error", input)
			}
		})
	}
}

func TestAutoApproverEditsRejectUnsupportedSelectorKinds(t *testing.T) {
	t.Parallel()
	for _, selector := range []string{
		"web",
		"ipset:corp",
		"ipset:corp@example.com",
		"100.64.0.1",
		"10.0.0.0/8",
		"*",
		"group:",
		"autogroup:",
		"tag:",
	} {
		t.Run(selector, func(t *testing.T) {
			t.Parallel()
			for _, operation := range []struct {
				name string
				edit func() (aclpolicy.AutoApproverEdit, error)
			}{
				{
					"add route",
					func() (aclpolicy.AutoApproverEdit, error) {
						return aclpolicy.AddRouteApprovers(
							mustLoad(t, `{}`), "10.0.0.0/8", []string{selector})
					},
				},
				{
					"remove route",
					func() (aclpolicy.AutoApproverEdit, error) {
						return aclpolicy.RemoveRouteApprovers(
							mustLoad(t, `{}`), "10.0.0.0/8", []string{selector})
					},
				},
				{
					"add exit node",
					func() (aclpolicy.AutoApproverEdit, error) {
						return aclpolicy.AddExitNodeApprovers(mustLoad(t, `{}`), []string{selector})
					},
				},
				{
					"remove exit node",
					func() (aclpolicy.AutoApproverEdit, error) {
						return aclpolicy.RemoveExitNodeApprovers(mustLoad(t, `{}`), []string{selector})
					},
				},
			} {
				t.Run(operation.name, func(t *testing.T) {
					t.Parallel()
					_, err := operation.edit()
					if err == nil {
						t.Fatalf("selector %q accepted, want error", selector)
					}
					if !strings.Contains(err.Error(), selector) ||
						!strings.Contains(err.Error(), "login email") {
						t.Errorf("error = %q, want selector and allowed kinds", err)
					}
				})
			}
		})
	}
}

func TestAutoApproverEditsAcceptSupportedSelectorKinds(t *testing.T) {
	t.Parallel()
	for _, selector := range []string{
		"alice@example.com",
		"alice@github",
		"group:network-admins",
		"group:security-team@example.com",
		"autogroup:admin",
		"autogroup:future-role",
		"user:*@example.com",
		"tag:router",
	} {
		t.Run(selector, func(t *testing.T) {
			t.Parallel()
			if _, err := aclpolicy.AddRouteApprovers(
				mustLoad(t, `{}`), "10.0.0.0/8", []string{selector}); err != nil {
				t.Errorf("supported selector %q rejected: %v", selector, err)
			}
		})
	}
}

// applyAutoApproverEdit writes content, applies edit, and returns the raw
// bytes and reloaded policy so a test can assert both the typed result and
// the byte-level preservation the hujson.Patch writer guarantees.
func applyAutoApproverEdit(
	t *testing.T,
	content string,
	edit aclpolicy.AutoApproverEdit,
) (string, *aclpolicy.Policy) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "acl.hujson")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := aclpolicy.WritePatch(path, edit.Operations...); err != nil {
		t.Fatalf("WritePatch: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := aclpolicy.Load(path)
	if err != nil {
		t.Fatalf("edited policy no longer loads: %v\n%s", err, raw)
	}
	return string(raw), policy
}

// addRoutes and removeRoutes apply one route edit end to end. The route is
// fixed because every case below edits the same CIDR; the merge and prune
// cases distinguish themselves through the fixture, not the argument.
func addRoutes(t *testing.T, content string, approvers ...string) (string, *aclpolicy.Policy) {
	t.Helper()
	policy := mustLoad(t, content)
	edit, err := aclpolicy.AddRouteApprovers(policy, "10.0.0.0/8", approvers)
	if err != nil {
		t.Fatalf("AddRouteApprovers: %v", err)
	}
	return applyAutoApproverEdit(t, content, edit)
}

func mustLoad(t *testing.T, content string) *aclpolicy.Policy {
	t.Helper()
	policy, err := aclpolicy.LoadBytes("test.hujson", []byte(content))
	if err != nil {
		t.Fatal(err)
	}
	return policy
}

func TestAddRouteApproversCreatesEachBlockLevel(t *testing.T) {
	t.Parallel()
	t.Run("no autoApprovers key", func(t *testing.T) {
		t.Parallel()
		_, policy := addRoutes(t, "{}", "group:neteng")
		got := policy.AutoApprovers.Routes["10.0.0.0/8"]
		if !slices.Equal(got, []string{"group:neteng"}) {
			t.Errorf("routes = %v", got)
		}
	})
	t.Run("no routes key", func(t *testing.T) {
		t.Parallel()
		_, policy := addRoutes(t, `{"autoApprovers": {"exitNode": ["tag:exit"]}}`, "group:neteng")
		if got := policy.AutoApprovers.Routes["10.0.0.0/8"]; !slices.Equal(got, []string{"group:neteng"}) {
			t.Errorf("routes = %v", got)
		}
		if !slices.Equal(policy.AutoApprovers.ExitNode, []string{"tag:exit"}) {
			t.Errorf("exitNode = %v, want preserved", policy.AutoApprovers.ExitNode)
		}
	})
	t.Run("new route key beside an existing one", func(t *testing.T) {
		t.Parallel()
		_, policy := addRoutes(t,
			`{"autoApprovers": {"routes": {"192.168.0.0/24": ["group:ops"]}}}`,
			"group:neteng", "tag:router")
		routes := policy.AutoApprovers.Routes
		if len(routes) != 2 ||
			!slices.Equal(routes["10.0.0.0/8"], []string{"group:neteng", "tag:router"}) ||
			!slices.Equal(routes["192.168.0.0/24"], []string{"group:ops"}) {
			t.Errorf("routes = %v", routes)
		}
	})
	t.Run("merge appends into an existing list", func(t *testing.T) {
		t.Parallel()
		_, policy := addRoutes(t,
			`{"autoApprovers": {"routes": {"10.0.0.0/8": ["group:ops"]}}}`,
			"group:ops", "group:neteng")
		got := policy.AutoApprovers.Routes["10.0.0.0/8"]
		if !slices.Equal(got, []string{"group:ops", "group:neteng"}) {
			t.Errorf("routes = %v, want merge, not replacement", got)
		}
	})
}

func TestAddRouteApproversIsIdempotentAndCanonicalizes(t *testing.T) {
	t.Parallel()
	policy := mustLoad(t, `{"autoApprovers": {"routes": {"10.0.0.0/8": ["group:ops", "group:neteng"]}}}`)

	// An unmasked spelling of the same route, an already-present approver, and
	// a duplicated argument must produce exactly one appended approver.
	edit, err := aclpolicy.AddRouteApprovers(policy, "10.9.9.9/8",
		[]string{"group:neteng", "tag:router", "tag:router"})
	if err != nil {
		t.Fatal(err)
	}
	if len(edit.Operations) != 1 {
		t.Errorf("operations = %d, want exactly one append", len(edit.Operations))
	}

	edit, err = aclpolicy.AddRouteApprovers(policy, "10.0.0.0/8", []string{"group:ops", "group:neteng"})
	if err != nil {
		t.Fatal(err)
	}
	if edit.Changed() {
		t.Error("re-adding existing approvers produced operations, want none")
	}
}

func TestAddExitNodeApprovers(t *testing.T) {
	t.Parallel()
	_, policy := addExitNode(t, `{}`, "tag:exit")
	if !slices.Equal(policy.AutoApprovers.ExitNode, []string{"tag:exit"}) {
		t.Errorf("exitNode = %v", policy.AutoApprovers.ExitNode)
	}

	_, policy = addExitNode(t, `{"autoApprovers": {"exitNode": ["tag:exit"]}}`, "tag:exit", "group:ops")
	if !slices.Equal(policy.AutoApprovers.ExitNode, []string{"tag:exit", "group:ops"}) {
		t.Errorf("exitNode = %v, want merged", policy.AutoApprovers.ExitNode)
	}

	if _, err := aclpolicy.AddExitNodeApprovers(mustLoad(t, `{}`), nil); err == nil {
		t.Error("add with no approvers accepted, want error")
	}
}

func addExitNode(t *testing.T, content string, approvers ...string) (string, *aclpolicy.Policy) {
	t.Helper()
	edit, err := aclpolicy.AddExitNodeApprovers(mustLoad(t, content), approvers)
	if err != nil {
		t.Fatalf("AddExitNodeApprovers: %v", err)
	}
	return applyAutoApproverEdit(t, content, edit)
}

func removeRoutes(t *testing.T, content string, approvers ...string) (string, *aclpolicy.Policy) {
	t.Helper()
	edit, err := aclpolicy.RemoveRouteApprovers(mustLoad(t, content), "10.0.0.0/8", approvers)
	if err != nil {
		t.Fatalf("RemoveRouteApprovers: %v", err)
	}
	return applyAutoApproverEdit(t, content, edit)
}

func TestRemoveRouteApproversPrunesEmptiedRouteKey(t *testing.T) {
	t.Parallel()
	t.Run("absent approver is a no-op", func(t *testing.T) {
		t.Parallel()
		policy := mustLoad(t, `{"autoApprovers": {"routes": {"10.0.0.0/8": ["group:ops"]}}}`)
		edit, err := aclpolicy.RemoveRouteApprovers(policy, "10.0.0.0/8", []string{"group:ghost"})
		if err != nil {
			t.Fatal(err)
		}
		if edit.Changed() {
			t.Error("removing an absent approver produced operations, want none")
		}
	})
	t.Run("partial removal keeps the survivors in order", func(t *testing.T) {
		t.Parallel()
		_, policy := removeRoutes(t,
			`{"autoApprovers": {"routes": {"10.0.0.0/8": ["group:a", "group:b", "group:c"]}}}`,
			"group:a", "group:c")
		if got := policy.AutoApprovers.Routes["10.0.0.0/8"]; !slices.Equal(got, []string{"group:b"}) {
			t.Errorf("routes = %v, want [group:b]", got)
		}
	})
	t.Run("emptied list prunes only the route key", func(t *testing.T) {
		t.Parallel()
		raw, policy := removeRoutes(t,
			`{"autoApprovers": {"routes": {"10.0.0.0/8": ["group:neteng"], "192.168.0.0/24": ["group:ops"]}}}`,
			"group:neteng")
		if len(policy.AutoApprovers.Routes) != 1 ||
			!slices.Equal(policy.AutoApprovers.Routes["192.168.0.0/24"], []string{"group:ops"}) {
			t.Errorf("routes = %v", policy.AutoApprovers.Routes)
		}
		if strings.Contains(raw, "10.0.0.0/8") {
			t.Errorf("emptied route key was not pruned:\n%s", raw)
		}
	})
	t.Run("duplicates in hand-edited input are removed together", func(t *testing.T) {
		t.Parallel()
		_, policy := removeRoutes(t,
			`{"autoApprovers": {"routes": {"10.0.0.0/8": ["group:a", "group:a"]}}}`,
			"group:a")
		if policy.AutoApprovers == nil || len(policy.AutoApprovers.Routes) != 0 {
			t.Errorf("autoApprovers = %v, want routes emptied", policy.AutoApprovers)
		}
	})
}

// A block emptied by a removal is emptied, never deleted — the rule grant
// remove and posture remove already apply to top-level keys, so a comment
// attached to the block is not carried out with its last entry.
func TestRemoveRouteApproversEmptiesBlocksWithoutDeletingThem(t *testing.T) {
	t.Parallel()
	t.Run("last route key empties routes but keeps the block and exitNode", func(t *testing.T) {
		t.Parallel()
		raw, policy := removeRoutes(t,
			`{"autoApprovers": {"routes": {"10.0.0.0/8": ["group:neteng"]}, "exitNode": ["tag:exit"]}}`,
			"group:neteng")
		if len(policy.AutoApprovers.Routes) != 0 {
			t.Errorf("routes = %v, want emptied", policy.AutoApprovers.Routes)
		}
		if !slices.Equal(policy.AutoApprovers.ExitNode, []string{"tag:exit"}) {
			t.Errorf("exitNode = %v, want preserved", policy.AutoApprovers.ExitNode)
		}
		if !strings.Contains(raw, `"routes"`) {
			t.Errorf("routes block was deleted instead of emptied:\n%s", raw)
		}
	})
	t.Run("emptying the last member keeps the section", func(t *testing.T) {
		t.Parallel()
		raw, policy := removeRoutes(t,
			`{"autoApprovers": {"routes": {"10.0.0.0/8": ["group:neteng"]}}, "grants": []}`,
			"group:neteng")
		if policy.AutoApprovers == nil {
			t.Error("autoApprovers was deleted instead of emptied")
		}
		if !strings.Contains(raw, "autoApprovers") {
			t.Errorf("autoApprovers block was deleted instead of emptied:\n%s", raw)
		}
	})
	t.Run("services survives an emptied routes block", func(t *testing.T) {
		t.Parallel()
		_, policy := removeRoutes(t,
			`{"autoApprovers": {"routes": {"10.0.0.0/8": ["group:neteng"]}, "services": {"svc:web": ["group:ops"]}}}`,
			"group:neteng")
		if policy.AutoApprovers == nil ||
			!slices.Equal(policy.AutoApprovers.Services["svc:web"], []string{"group:ops"}) {
			t.Errorf("autoApprovers = %v, want services preserved", policy.AutoApprovers)
		}
	})
}

func TestRemoveExitNodeApprovers(t *testing.T) {
	t.Parallel()
	t.Run("partial removal keeps order", func(t *testing.T) {
		t.Parallel()
		edit, err := aclpolicy.RemoveExitNodeApprovers(
			mustLoad(t, `{"autoApprovers": {"exitNode": ["tag:a", "tag:b", "tag:c"]}}`),
			[]string{"tag:a", "tag:c"})
		if err != nil {
			t.Fatal(err)
		}
		_, policy := applyAutoApproverEdit(t,
			`{"autoApprovers": {"exitNode": ["tag:a", "tag:b", "tag:c"]}}`, edit)
		if !slices.Equal(policy.AutoApprovers.ExitNode, []string{"tag:b"}) {
			t.Errorf("exitNode = %v, want [tag:b]", policy.AutoApprovers.ExitNode)
		}
	})
	t.Run("emptied list prunes the member but keeps the section", func(t *testing.T) {
		t.Parallel()
		raw, policy := removeExitNode(t,
			`{"autoApprovers": {"routes": {"10.0.0.0/8": ["group:ops"]}, "exitNode": ["tag:exit"]}}`,
			"tag:exit")
		if policy.AutoApprovers.ExitNode != nil {
			t.Errorf("exitNode = %v, want pruned", policy.AutoApprovers.ExitNode)
		}
		if strings.Contains(raw, "exitNode") {
			t.Errorf("emptied exitNode member was not pruned:\n%s", raw)
		}

		raw, policy = removeExitNode(t, `{"autoApprovers": {"exitNode": ["tag:exit"]}}`, "tag:exit")
		if policy.AutoApprovers == nil {
			t.Error("autoApprovers was deleted instead of emptied")
		}
		if !strings.Contains(raw, "autoApprovers") {
			t.Errorf("autoApprovers block was deleted instead of emptied:\n%s", raw)
		}
	})
}

// TestAddExitNodeApproversCreatesMemberInExistingBlock covers the one
// exit-node write branch no other test reaches: an autoApprovers block that
// exists but carries no exitNode member. Its route twin ("no routes key") is
// covered by TestAddRouteApproversCreatesEachBlockLevel; this side was not.
func TestAddExitNodeApproversCreatesMemberInExistingBlock(t *testing.T) {
	t.Parallel()
	const content = `{"autoApprovers": {"routes": {"10.0.0.0/8": ["group:ops"]}}}`
	raw, policy := addExitNode(t, content, "tag:exit")
	if !slices.Equal(policy.AutoApprovers.ExitNode, []string{"tag:exit"}) {
		t.Errorf("exitNode = %v, want the created member", policy.AutoApprovers.ExitNode)
	}
	if !slices.Equal(policy.AutoApprovers.Routes["10.0.0.0/8"], []string{"group:ops"}) {
		t.Errorf("routes = %v, want the sibling member preserved:\n%s",
			policy.AutoApprovers.Routes, raw)
	}
}

// TestAutoApproverExitNodeEditsAreIdempotent pins the exit-node half of the
// idempotency the README and the -schema catalog both promise. The route half
// is covered by TestAddRouteApproversIsIdempotentAndCanonicalizes; a promise
// stated for both sections was tested for one.
func TestAutoApproverExitNodeEditsAreIdempotent(t *testing.T) {
	t.Parallel()
	edit, err := aclpolicy.AddExitNodeApprovers(
		mustLoad(t, `{"autoApprovers": {"exitNode": ["tag:exit"]}}`), []string{"tag:exit"})
	if err != nil {
		t.Fatal(err)
	}
	if edit.Changed() {
		t.Errorf("re-adding a present approver produced %d operation(s), want none",
			len(edit.Operations))
	}
	edit, err = aclpolicy.RemoveExitNodeApprovers(
		mustLoad(t, `{"autoApprovers": {"exitNode": ["tag:exit"]}}`), []string{"tag:absent"})
	if err != nil {
		t.Fatal(err)
	}
	if edit.Changed() {
		t.Errorf("removing an absent approver produced %d operation(s), want none",
			len(edit.Operations))
	}
}

// TestAutoApproverRemoveWithoutBlockIsANoOp covers the nil-block early returns,
// which guard the dereference on the line after each of them.
func TestAutoApproverRemoveWithoutBlockIsANoOp(t *testing.T) {
	t.Parallel()
	routeEdit, err := aclpolicy.RemoveRouteApprovers(mustLoad(t, `{}`), "10.0.0.0/8", []string{"group:ops"})
	if err != nil {
		t.Fatal(err)
	}
	if routeEdit.Changed() {
		t.Errorf("route remove against an absent block produced %d operation(s)", len(routeEdit.Operations))
	}
	// Route survives the early return so a caller naming the edited node does
	// not fall through to AutoApproverSegments("") and address exitNode.
	if routeEdit.Route != "10.0.0.0/8" {
		t.Errorf("Route = %q, want the requested prefix", routeEdit.Route)
	}
	exitEdit, err := aclpolicy.RemoveExitNodeApprovers(mustLoad(t, `{}`), []string{"tag:exit"})
	if err != nil {
		t.Fatal(err)
	}
	if exitEdit.Changed() {
		t.Errorf("exit-node remove against an absent block produced %d operation(s)", len(exitEdit.Operations))
	}
}

// TestAutoApproverRefusesAmbiguousRouteSpelling pins the refusal that replaced
// first-match-wins. Two keys naming one prefix is reachable from "merge --dir"
// over fragments that spell an IPv6 prefix in different case, and editing
// either one would report success while the other kept approving the prefix.
func TestAutoApproverRefusesAmbiguousRouteSpelling(t *testing.T) {
	t.Parallel()
	const content = `{"autoApprovers": {"routes": {
		"2001:DB8::/32": ["group:ops"],
		"2001:db8::/32": ["group:ops"],
	}}}`
	for name, edit := range map[string]func() (aclpolicy.AutoApproverEdit, error){
		"add": func() (aclpolicy.AutoApproverEdit, error) {
			return aclpolicy.AddRouteApprovers(mustLoad(t, content), "2001:db8::/32", []string{"group:new"})
		},
		"remove": func() (aclpolicy.AutoApproverEdit, error) {
			return aclpolicy.RemoveRouteApprovers(mustLoad(t, content), "2001:db8::/32", []string{"group:ops"})
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := edit()
			if err == nil {
				t.Fatal("ambiguous route spelling accepted, want an error naming both keys")
			}
			for _, want := range []string{"2001:DB8::/32", "2001:db8::/32"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q does not name %q", err, want)
				}
			}
		})
	}
}

func removeExitNode(t *testing.T, content string, approvers ...string) (string, *aclpolicy.Policy) {
	t.Helper()
	edit, err := aclpolicy.RemoveExitNodeApprovers(mustLoad(t, content), approvers)
	if err != nil {
		t.Fatalf("RemoveExitNodeApprovers: %v", err)
	}
	return applyAutoApproverEdit(t, content, edit)
}

func TestAutoApproverSegments(t *testing.T) {
	t.Parallel()
	if got, want := aclpolicy.AutoApproverSegments("10.0.0.0/8"),
		[]string{"autoApprovers", "routes", "10.0.0.0/8"}; !slices.Equal(got, want) {
		t.Errorf("route segments = %v, want %v", got, want)
	}
	if got, want := aclpolicy.AutoApproverSegments(""),
		[]string{"autoApprovers", "exitNode"}; !slices.Equal(got, want) {
		t.Errorf("exit-node segments = %v, want %v", got, want)
	}
}
