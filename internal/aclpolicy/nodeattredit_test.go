package aclpolicy_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/tailscale/hujson"
	tailscale "tailscale.com/client/tailscale/v2"

	"github.com/rshade/tail-acl/internal/aclpolicy"
)

func TestNodeAttrAddMergesTargetSetAndPreservesApp(t *testing.T) {
	t.Parallel()
	const original = `{
	// The app block is owned by the connector team.
	"nodeAttrs": [{
		"target": ["tag:app"],
		"app": {
			// Keep this nested comment and key order intact.
			"tailscale.com/app-connectors": [{
				"name":       "github",
				"connectors": ["tag:connector"],
				"domains": ["github.com"],
			}],
		},
	}],
}

`
	path := filepath.Join(t.TempDir(), "acl.hujson")
	if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	policy, err := aclpolicy.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	edit, err := aclpolicy.AddNodeAttr(policy, aclpolicy.NodeAttrSpec{
		Target: []string{"tag:app"}, Attr: []string{"funnel"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !edit.Changed() || edit.EntryIndex != 0 {
		t.Fatalf("edit = %#v, want one change to entry 0", edit)
	}
	if err = aclpolicy.WritePatch(path, edit.Operations...); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	const appBlock = `"app": {
			// Keep this nested comment and key order intact.
			"tailscale.com/app-connectors": [{
				"name":       "github",
				"connectors": ["tag:connector"],
				"domains":    ["github.com"],
			}],
		}`
	if !strings.Contains(string(got), appBlock) {
		t.Errorf("app block was not byte-preserved:\n%s", got)
	}
	if !strings.Contains(string(got), `"attr":`) || !strings.Contains(string(got), `"funnel"`) {
		t.Errorf("attribute was not merged:\n%s", got)
	}
	if _, err = aclpolicy.Load(path); err != nil {
		t.Fatalf("edited policy no longer loads: %v\n%s", err, got)
	}
}

func TestMergeDedupesNodeAttrsWithReorderedTargetLists(t *testing.T) {
	t.Parallel()
	dst, err := hujson.Parse([]byte(`{"nodeAttrs":[{"target":["tag:one","tag:two"],"attr":["funnel"]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	src, err := hujson.Parse([]byte(`{"nodeAttrs":[{"target":["tag:two","tag:one"],"attr":["funnel"]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if err = aclpolicy.MergeInto(&dst, &src); err != nil {
		t.Fatal(err)
	}
	standard, err := hujson.Standardize(dst.Pack())
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		NodeAttrs []map[string]any `json:"nodeAttrs"`
	}
	if err = json.Unmarshal(standard, &document); err != nil {
		t.Fatal(err)
	}
	if len(document.NodeAttrs) != 1 {
		t.Fatalf("merged nodeAttrs = %#v, want one semantic entry", document.NodeAttrs)
	}
}

// TestNodeAttrIPPoolIsCanonicalized locks the pool spelling authored into the
// file to the masked prefix, matching NormalizeIPSetCIDR and
// NormalizeAutoApproverRoute. Without it two spellings of one network author
// two pool entries that merge's string-keyed dedup cannot collapse, while
// nodeAttrValuesEqual already treats them as the same value.
func TestNodeAttrIPPoolIsCanonicalized(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.hujson")
	if err := os.WriteFile(path, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	policy, err := aclpolicy.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	edit, err := aclpolicy.AddNodeAttr(policy, aclpolicy.NodeAttrSpec{
		Target: []string{"tag:app"}, IPPool: []string{"100.81.0.5/16"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = aclpolicy.WritePatch(path, edit.Operations...); err != nil {
		t.Fatal(err)
	}
	updated, err := aclpolicy.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(updated.NodeAttrs) != 1 || len(updated.NodeAttrs[0].IPPool) != 1 ||
		updated.NodeAttrs[0].IPPool[0] != "100.81.0.0/16" {
		t.Fatalf("authored ipPool = %#v, want the masked prefix", updated.NodeAttrs)
	}
	again, err := aclpolicy.AddNodeAttr(updated, aclpolicy.NodeAttrSpec{
		Target: []string{"tag:app"}, IPPool: []string{"100.81.0.0/16"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if again.Changed() {
		t.Errorf("re-adding the same network = %#v, want no change", again)
	}
}

// TestMergeKeepsGrantAppPayloadOrderSignificant guards the blast radius of
// treating nodeAttrs member names as sets. grants[].app is an opaque
// third-party capability payload, so a member there named target, attr,
// ipPool, connectors, or domains means whatever the capability says and its
// order is identity. Sorting it makes two distinct grants share a semantic key
// and merge drops one of them without a word.
func TestMergeKeepsGrantAppPayloadOrderSignificant(t *testing.T) {
	t.Parallel()
	for _, field := range []string{"target", "attr", "ipPool", "connectors", "domains"} {
		t.Run(field, func(t *testing.T) {
			t.Parallel()
			dst, err := hujson.Parse([]byte(`{"grants":[{"src":["tag:a"],"dst":["tag:b"],"ip":["*"],
				"app":{"example.com/cap":[{"` + field + `":["stage1","stage2"]}]}}]}`))
			if err != nil {
				t.Fatal(err)
			}
			src, err := hujson.Parse([]byte(`{"grants":[{"src":["tag:a"],"dst":["tag:b"],"ip":["*"],
				"app":{"example.com/cap":[{"` + field + `":["stage2","stage1"]}]}}]}`))
			if err != nil {
				t.Fatal(err)
			}
			if err = aclpolicy.MergeInto(&dst, &src); err != nil {
				t.Fatal(err)
			}
			standard, err := hujson.Standardize(dst.Pack())
			if err != nil {
				t.Fatal(err)
			}
			var document struct {
				Grants []map[string]any `json:"grants"`
			}
			if err = json.Unmarshal(standard, &document); err != nil {
				t.Fatal(err)
			}
			if len(document.Grants) != 2 {
				t.Errorf("merged grants = %d, want both payload orders retained: %s", len(document.Grants), standard)
			}
		})
	}
}

// TestMergeStillSortsNodeAttrAppConnectors is the other half: inside nodeAttrs
// the same member names are the pinned NodeAttrGrantApp's selector lists, so
// they must still compare as sets.
func TestMergeStillSortsNodeAttrAppConnectors(t *testing.T) {
	t.Parallel()
	dst, err := hujson.Parse([]byte(`{"nodeAttrs":[{"target":["tag:a"],
		"app":{"tailscale.com/app-connectors":[{"connectors":["tag:one","tag:two"]}]}}]}`))
	if err != nil {
		t.Fatal(err)
	}
	src, err := hujson.Parse([]byte(`{"nodeAttrs":[{"target":["tag:a"],
		"app":{"tailscale.com/app-connectors":[{"connectors":["tag:two","tag:one"]}]}}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if err = aclpolicy.MergeInto(&dst, &src); err != nil {
		t.Fatal(err)
	}
	standard, err := hujson.Standardize(dst.Pack())
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		NodeAttrs []map[string]any `json:"nodeAttrs"`
	}
	if err = json.Unmarshal(standard, &document); err != nil {
		t.Fatal(err)
	}
	if len(document.NodeAttrs) != 1 {
		t.Fatalf("merged nodeAttrs = %d, want one semantic entry: %s", len(document.NodeAttrs), standard)
	}
}

func TestNodeAttrAddAndRemoveAreIdempotentAndPruneDuplicates(t *testing.T) {
	t.Parallel()
	const original = `{
		"nodeAttrs": [
			{"target": ["tag:one", "tag:two"], "attr": ["funnel", "funnel", "service-expose"]},
			{"target": ["tag:two", "tag:one"], "attr": ["funnel"]},
			{"target": ["tag:other"], "attr": ["funnel"]}
		]
	}`
	path := filepath.Join(t.TempDir(), "acl.hujson")
	if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	policy, err := aclpolicy.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	edit, err := aclpolicy.AddNodeAttr(policy, aclpolicy.NodeAttrSpec{
		Target: []string{"tag:two", "tag:one"}, Attr: []string{"funnel", "new-opaque-attribute"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !edit.Changed() || edit.EntryIndex != 0 {
		t.Fatalf("merge edit = %#v, want entry 0 changed", edit)
	}
	if len(edit.Operations) != 1 {
		t.Fatalf("merge operations = %d, want one append", len(edit.Operations))
	}
	remove, err := aclpolicy.RemoveNodeAttr(policy, aclpolicy.NodeAttrSpec{
		Target: []string{"tag:one", "tag:two"}, Attr: []string{"funnel"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !remove.Changed() || len(remove.Operations) != 3 {
		t.Fatalf("remove edit = %#v, want both duplicate entries", remove)
	}
	if err = aclpolicy.WritePatch(path, remove.Operations...); err != nil {
		t.Fatal(err)
	}
	updated, err := aclpolicy.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(updated.NodeAttrs) != 2 || len(updated.NodeAttrs[0].Attr) != 1 ||
		updated.NodeAttrs[0].Attr[0] != "service-expose" {
		t.Fatalf("removed nodeAttrs = %#v, want one duplicate pruned and one value retained", updated.NodeAttrs)
	}
}

// TestNodeAttrAddSeesValuesInEveryMatchingEntry covers a value that is already
// in effect under the requested target set but lives in a later entry than the
// first one matching it. AddNodeAttr must report no change: writing the value
// into the first entry duplicates it, and the natural undo then strips it from
// both entries and prunes the pre-existing one, destroying policy the add never
// created. RemoveNodeAttr already scans every matching entry, so an add that
// stops at the first is the half that breaks the round trip.
func TestNodeAttrAddSeesValuesInEveryMatchingEntry(t *testing.T) {
	t.Parallel()
	const original = `{
		"nodeAttrs": [
			{"target": ["tag:a"], "ipPool": ["100.64.0.0/10"]},
			{"target": ["tag:a"], "attr": ["funnel"]}
		]
	}`
	path := filepath.Join(t.TempDir(), "acl.hujson")
	if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	policy, err := aclpolicy.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	edit, err := aclpolicy.AddNodeAttr(policy, aclpolicy.NodeAttrSpec{
		Target: []string{"tag:a"}, Attr: []string{"funnel"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if edit.Changed() {
		t.Fatalf("add operations = %#v, want none: funnel is already in effect for tag:a", edit.Operations)
	}
}

// TestNodeAttrAddStillFillsGapsAcrossMatchingEntries pins the other half of the
// scan: a value absent from every matching entry is still authored, and lands
// in the first matching entry so comment routing stays where the docs say.
func TestNodeAttrAddStillFillsGapsAcrossMatchingEntries(t *testing.T) {
	t.Parallel()
	const original = `{
		"nodeAttrs": [
			{"target": ["tag:a"], "attr": ["funnel"]},
			{"target": ["tag:a"], "attr": ["nextdns"]}
		]
	}`
	path := filepath.Join(t.TempDir(), "acl.hujson")
	if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	policy, err := aclpolicy.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	edit, err := aclpolicy.AddNodeAttr(policy, aclpolicy.NodeAttrSpec{
		Target: []string{"tag:a"}, Attr: []string{"funnel", "nextdns", "service-expose"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !edit.Changed() || edit.EntryIndex != 0 {
		t.Fatalf("add edit = %#v, want the one missing value written to entry 0", edit)
	}
	if err = aclpolicy.WritePatch(path, edit.Operations...); err != nil {
		t.Fatal(err)
	}
	updated, err := aclpolicy.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := updated.NodeAttrs[0].Attr; len(got) != 2 || got[1] != "service-expose" {
		t.Errorf("entry 0 attr = %#v, want only the absent value appended", got)
	}
	if got := updated.NodeAttrs[1].Attr; len(got) != 1 {
		t.Errorf("entry 1 attr = %#v, want untouched", got)
	}
}

// TestMergeKeepsGrantAppPayloadOrderSignificantForLegacyKeys extends the guard
// above to the two cases it did not reach. The payload member names that are
// sorted regardless of section (src, dst, ip, users, srcPosture, via) are the
// ones that leak through the section gate, and the gate is keyed on an exact
// "app", while Tailscale's legacy policy style capitalizes section and member
// names — resolveTopLevelKey exists precisely because that spelling is
// supported. merge never calls Load, so it sees whatever spelling the fragment
// uses, and a missed gate silently drops one of two distinct grants.
func TestMergeKeepsGrantAppPayloadOrderSignificantForLegacyKeys(t *testing.T) {
	t.Parallel()
	type payloadCase struct{ appKey, field string }
	var cases []payloadCase
	for _, appKey := range []string{"app", "App"} {
		for _, field := range []string{"src", "dst", "ip", "users", "srcPosture", "via", "connectors"} {
			cases = append(cases, payloadCase{appKey, field})
		}
	}
	for _, test := range cases {
		t.Run(test.appKey+"/"+test.field, func(t *testing.T) {
			t.Parallel()
			document := func(first, second string) string {
				return `{"grants":[{"src":["tag:a"],"dst":["tag:b"],"ip":["*"],"` + test.appKey +
					`":{"example.com/cap":[{"` + test.field + `":["` + first + `","` + second + `"]}]}}]}`
			}
			grants := mergedGrantCount(t, document("stage1", "stage2"), document("stage2", "stage1"))
			if grants != 2 {
				t.Errorf("merged grants = %d, want both payload orders retained", grants)
			}
		})
	}
}

// mergedGrantCount merges src into dst and reports how many grants survived.
func mergedGrantCount(t *testing.T, dstDocument, srcDocument string) int {
	t.Helper()
	dst, err := hujson.Parse([]byte(dstDocument))
	if err != nil {
		t.Fatal(err)
	}
	src, err := hujson.Parse([]byte(srcDocument))
	if err != nil {
		t.Fatal(err)
	}
	if err = aclpolicy.MergeInto(&dst, &src); err != nil {
		t.Fatal(err)
	}
	standard, err := hujson.Standardize(dst.Pack())
	if err != nil {
		t.Fatal(err)
	}
	var parsed struct {
		Grants []map[string]any `json:"grants"`
	}
	if err = json.Unmarshal(standard, &parsed); err != nil {
		t.Fatal(err)
	}
	return len(parsed.Grants)
}

// TestNodeAttrGrantFieldsAreAccountedForByPruning is a Tier-2 provenance guard
// (AX convention 13) over nodeAttrEntryEmptyAfter, which decides whether
// removing the last attr or ipPool prunes the whole entry. That function is a
// third hand-maintained enumeration of NodeAttrGrant's fields, alongside the two
// reference walks AGENTS.md already warns about — and it is the one that
// deletes. A new data-bearing field would be populated by Load, ignored by the
// emptiness test, and destroyed by the entry-level PatchRemove while the command
// reported ok: no compile error, no golden diff, nothing failing loudly. This
// test is that missing alarm.
func TestNodeAttrGrantFieldsAreAccountedForByPruning(t *testing.T) {
	t.Parallel()
	var fields []string
	for field := range reflect.TypeFor[tailscale.NodeAttrGrant]().Fields() {
		tag, _, _ := strings.Cut(field.Tag.Get("json"), ",")
		if tag != "" && tag != "-" {
			fields = append(fields, tag)
		}
	}
	slices.Sort(fields)
	// target is the match key; attr, ipPool, and app are the data
	// nodeAttrEntryEmptyAfter weighs before pruning an entry.
	want := []string{"app", "attr", "ipPool", "target"}
	if !slices.Equal(fields, want) {
		t.Fatalf("NodeAttrGrant json fields = %v, want %v; "+
			"a new data-bearing field must be added to nodeAttrEntryEmptyAfter or removal will destroy it",
			fields, want)
	}
}

// TestRemoveNodeAttrKeepsEntryCarryingAppData exercises the App arm of
// nodeAttrEntryEmptyAfter, the single check standing between nodeattr remove and
// deleting an operator's app-connector block.
func TestRemoveNodeAttrKeepsEntryCarryingAppData(t *testing.T) {
	t.Parallel()
	const original = `{
		"nodeAttrs": [
			{
				"target": ["tag:conn"],
				"attr": ["funnel"],
				"app": {"tailscale.com/app-connectors": [{"connectors": ["tag:conn"], "domains": ["example.com"]}]}
			}
		]
	}`
	path := filepath.Join(t.TempDir(), "acl.hujson")
	if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	policy, err := aclpolicy.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	edit, err := aclpolicy.RemoveNodeAttr(policy, aclpolicy.NodeAttrSpec{
		Target: []string{"tag:conn"}, Attr: []string{"funnel"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = aclpolicy.WritePatch(path, edit.Operations...); err != nil {
		t.Fatal(err)
	}
	updated, err := aclpolicy.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(updated.NodeAttrs) != 1 {
		t.Fatalf("nodeAttrs = %#v, want the app-bearing entry retained", updated.NodeAttrs)
	}
	if len(updated.NodeAttrs[0].Attr) != 0 {
		t.Errorf("attr = %#v, want emptied", updated.NodeAttrs[0].Attr)
	}
	apps := updated.NodeAttrs[0].App["tailscale.com/app-connectors"]
	if len(apps) != 1 || !slices.Equal(apps[0].Connectors, []string{"tag:conn"}) ||
		!slices.Equal(apps[0].Domains, []string{"example.com"}) {
		t.Errorf("app block = %#v, want preserved intact", updated.NodeAttrs[0].App)
	}
}

// TestRemoveNodeAttrMatchesNonCanonicalIPPool pins the removal half of IP-pool
// canonicalization: the file's spelling comes from a human, so the masked-prefix
// comparison has to settle it against the canonical value the CLI normalized to.
func TestRemoveNodeAttrMatchesNonCanonicalIPPool(t *testing.T) {
	t.Parallel()
	const original = `{"nodeAttrs": [{"target": ["tag:a"], "ipPool": ["100.81.0.5/16", "10.0.0.0/8"]}]}`
	path := filepath.Join(t.TempDir(), "acl.hujson")
	if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	policy, err := aclpolicy.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	edit, err := aclpolicy.RemoveNodeAttr(policy, aclpolicy.NodeAttrSpec{
		Target: []string{"tag:a"}, IPPool: []string{"100.81.0.0/16"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !edit.Changed() {
		t.Fatal("remove reported no change, want the non-canonical pool matched")
	}
	if err = aclpolicy.WritePatch(path, edit.Operations...); err != nil {
		t.Fatal(err)
	}
	updated, err := aclpolicy.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := updated.NodeAttrs[0].IPPool; !slices.Equal(got, []string{"10.0.0.0/8"}) {
		t.Errorf("ipPool = %#v, want only the unrelated pool retained", got)
	}
}

// TestAddNodeAttrIntoPresentButEmptyArray covers the one input where
// AddNodeAttr's nil check and runNodeAttrAdd's EntryIndex comment routing
// disagree: non-nil, length zero.
func TestAddNodeAttrIntoPresentButEmptyArray(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.hujson")
	if err := os.WriteFile(path, []byte(`{"nodeAttrs": []}`), 0o600); err != nil {
		t.Fatal(err)
	}
	policy, err := aclpolicy.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	edit, err := aclpolicy.AddNodeAttr(policy, aclpolicy.NodeAttrSpec{
		Target: []string{"tag:a"}, Attr: []string{"funnel"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if edit.EntryIndex != 0 {
		t.Fatalf("EntryIndex = %d, want 0 so the comment routes to the appended entry", edit.EntryIndex)
	}
	if err = aclpolicy.WritePatch(path, edit.Operations...); err != nil {
		t.Fatal(err)
	}
	updated, err := aclpolicy.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(updated.NodeAttrs) != 1 || !slices.Equal(updated.NodeAttrs[0].Attr, []string{"funnel"}) {
		t.Errorf("nodeAttrs = %#v, want one appended entry", updated.NodeAttrs)
	}
}
