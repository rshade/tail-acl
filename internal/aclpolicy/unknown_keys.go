package aclpolicy

import (
	"fmt"
	"maps"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/tailscale/hujson"
)

type policyKeyCatalog struct {
	modeled map[string]string
	nested  map[string][]string
}

const maxPolicyKeySuggestionDistance = 2

// isModeled reports whether name decodes into a modeled Policy field.
// encoding/json matches field names with Unicode simple case folding, which
// [strings.EqualFold] implements and a lowercased map key does not: a ToLower
// lookup rejects "ho\u017Fts" for "hosts", which the decoder behind this check
// accepts, and separately accepts U+0130 spellings the decoder rejects. One
// fold rule over 18 keys costs well under a microsecond, so the map is keyed
// for the catalog's own lookups rather than for this one.
func (c policyKeyCatalog) isModeled(name string) bool {
	for _, canonical := range c.modeled {
		if strings.EqualFold(canonical, name) {
			return true
		}
	}
	return false
}

// classify explains why one top-level key is not modeled. The catalog is a
// receiver rather than the package-level cache so a guard can drive every
// branch from a synthetic vocabulary.
//
// The residual verdict claims only what this code can prove. Reflecting over
// Policy establishes what the pinned client models; nothing here can testify
// to what Tailscale's syntax reference documents, and Tailscale ships policy
// keys in alpha and beta ahead of GA -- so a key this build does not model is
// routinely a real key the pin has not caught up to. Calling that "not a
// recognized Tailscale policy key" is a confident wrong answer that steers an
// operator toward deleting live policy out of their own tailnet. Naming the
// build instead leaves both readings open, the same discipline policycore.Match
// applies to a membership question it cannot settle. Run --version for the
// client pin the phrase refers to; it is deliberately not inlined here, because
// debug.ReadBuildInfo reports no dependencies under go test and the message
// would then differ between test and production.
func (c policyKeyCatalog) classify(name string) string {
	if paths := c.nested[strings.ToLower(name)]; len(paths) > 0 {
		return "known nested Tailscale policy key; use " + describeNestedLocations(paths)
	}
	detail := "not modeled by this build"
	if suggestion, ok := suggestPolicyKey(name, c.modeled); ok {
		detail += fmt.Sprintf("; did you mean %q?", suggestion)
	}
	return detail
}

// describeNestedLocations renders every location a nested policy key is valid
// at. Naming only the unambiguous single-location case left the eleven keys
// that appear in more than one rule object -- "src" and "dst" among them --
// reported as "not a recognized Tailscale policy key", which is false, and
// close enough to a modeled key to draw a misleading spelling hint.
func describeNestedLocations(paths []string) string {
	quoted := make([]string, len(paths))
	for i, path := range paths {
		quoted[i] = strconv.Quote(path)
	}
	if len(quoted) == 1 {
		return quoted[0]
	}
	return "one of " + strings.Join(quoted, ", ")
}

// policyKeyCatalogOnce caches the catalog. buildPolicyKeyCatalog reflects over
// the whole tailscale.ACL type tree and is a pure function of compile-time
// types, but rebuilding it per call cost more than the check it serves: about
// 26us and 317 allocations against well under a microsecond for the lookup
// itself, on every command that reads a policy. The cached maps are
// never written after construction, so sharing them across goroutines is a
// read-only share; tests call the builder directly for an unshared copy.
//
//nolint:gochecknoglobals // memoizes a compile-time-derived catalog for process lifetime; sync.OnceValue must be package-level.
var policyKeyCatalogOnce = sync.OnceValue(buildPolicyKeyCatalog)

// buildPolicyKeyCatalog derives the modeled keys and nested-key locations from
// the same JSON tags encoding/json uses to decode Policy, following the
// embedded tailscale.ACL to reach the fields it promotes.
func buildPolicyKeyCatalog() policyKeyCatalog {
	topLevel := jsonObjectFields(reflect.TypeFor[Policy]())
	modeled := make(map[string]string, len(topLevel))
	for key, field := range topLevel {
		modeled[key] = field.name
	}

	nested := make(map[string][]string)
	for _, field := range topLevel {
		collectNestedJSONFields(field.typ, field.name, nested, make(map[reflect.Type]bool))
	}
	for key := range nested {
		// Sort for a deterministic hint; compact because the dedup guarantee is
		// worth keeping cheaply even though every path carries its full prefix
		// and so is unique by construction.
		slices.Sort(nested[key])
		nested[key] = slices.Compact(nested[key])
	}
	return policyKeyCatalog{modeled: modeled, nested: nested}
}

type jsonObjectField struct {
	name string
	typ  reflect.Type
}

// jsonObjectFields returns the fields encoding/json exposes in one JSON
// object. An untagged anonymous struct is promoted, which is how Policy gets
// the fields of tailscale.ACL at its top level.
//
// It resolves a name collision by declaration order -- the last field wins --
// which is not encoding/json's rule. The decoder resolves by depth, preferring
// the shallower field and dropping both on a same-depth tie. The two agree on
// Policy only because tailscale.ACL is embedded above the SSH field that
// shadows it; TestPolicyKeyCatalogPrefersShadowingSSHField fails if that order
// changes. Reach for the depth rule here only when a second shadowed field or
// a second embedded struct makes the difference observable.
func jsonObjectFields(typ reflect.Type) map[string]jsonObjectField {
	for typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}
	fields := make(map[string]jsonObjectField)
	if typ.Kind() != reflect.Struct {
		return fields
	}
	for field := range typ.Fields() {
		if field.PkgPath != "" && !field.Anonymous {
			continue
		}
		name, tagged := jsonFieldName(field)
		if name == "-" {
			continue
		}
		if field.Anonymous && !tagged && isStructType(field.Type) {
			maps.Copy(fields, jsonObjectFields(field.Type))
			continue
		}
		fields[strings.ToLower(name)] = jsonObjectField{name: name, typ: field.Type}
	}
	return fields
}

func jsonFieldName(field reflect.StructField) (string, bool) {
	tag, hasTag := field.Tag.Lookup("json")
	if !hasTag {
		return field.Name, false
	}
	name, _, _ := strings.Cut(tag, ",")
	if name == "" {
		return field.Name, true
	}
	return name, true
}

func isStructType(typ reflect.Type) bool {
	for typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}
	return typ.Kind() == reflect.Struct
}

// collectNestedJSONFields records only paths that can name an object member;
// array and map element structs are followed because policy fields such as
// grants and autoApprovers contain objects at those levels. Each hop through a
// collection is written into the path -- "[]" for an array, ".<key>" for a map
// -- because a hint is only actionable if it names a location that exists:
// eliding them rendered attrConfig's per-attribute objects as "attrConfig.type",
// which reads as a struct path an operator cannot write.
func collectNestedJSONFields(
	typ reflect.Type,
	prefix string,
	locations map[string][]string,
	active map[reflect.Type]bool,
) {
	for {
		kind := typ.Kind()
		if kind == reflect.Pointer {
			typ = typ.Elem()
			continue
		}
		if kind == reflect.Slice || kind == reflect.Array {
			typ, prefix = typ.Elem(), prefix+"[]"
			continue
		}
		if kind == reflect.Map {
			typ, prefix = typ.Elem(), prefix+".<key>"
			continue
		}
		break
	}
	if typ.Kind() != reflect.Struct || active[typ] {
		return
	}
	active[typ] = true
	defer delete(active, typ)

	for key, field := range jsonObjectFields(typ) {
		path := prefix + "." + field.name
		locations[key] = append(locations[key], path)
		collectNestedJSONFields(field.typ, path, locations, active)
	}
}

func checkUnknownPolicyKeys(document hujson.Value) error {
	catalog := policyKeyCatalogOnce()
	object, ok := document.Value.(*hujson.Object)
	if !ok {
		return nil
	}

	var findings []string
	for _, member := range object.Members {
		literal, literalOK := member.Name.Value.(hujson.Literal)
		if !literalOK {
			continue
		}
		name := literal.String()
		if catalog.isModeled(name) {
			continue
		}
		findings = append(findings,
			fmt.Sprintf("unknown field %q (%s)", name, catalog.classify(name)))
	}
	if len(findings) == 0 {
		return nil
	}
	return fmt.Errorf("unknown top-level policy keys: %s", strings.Join(findings, "; "))
}

// suggestPolicyKey returns the closest modeled top-level key when the typo is
// close enough to be useful. Map iteration is deliberately not used to break
// ties: a stable hint is part of an operator-facing error and of the CLI's
// machine-consumed diagnostics.
func suggestPolicyKey(name string, modeled map[string]string) (string, bool) {
	name = strings.ToLower(name)
	nameRunes := utf8.RuneCountInString(name)
	best := ""
	bestDistance := maxPolicyKeySuggestionDistance + 1
	for key, canonical := range modeled {
		// A rune-count difference is an exact lower bound on edit distance, so
		// this rejects only keys the full comparison would have rejected. It
		// also keeps an oversized object name out of an O(len(name)*len(key))
		// matrix run once per modeled key: a megabyte-long key cannot be within
		// two edits of any of them, but measuring that costs a rune slice each.
		if delta := nameRunes - utf8.RuneCountInString(key); delta > maxPolicyKeySuggestionDistance ||
			delta < -maxPolicyKeySuggestionDistance {
			continue
		}
		distance := levenshteinDistance(name, key)
		if distance > maxPolicyKeySuggestionDistance || distance > bestDistance {
			continue
		}
		// best is always set whenever bestDistance is in range, so this needs no
		// first-iteration guard: an unset best pairs with a distance the filter
		// above already dropped.
		if distance == bestDistance && canonical >= best {
			continue
		}
		best = canonical
		bestDistance = distance
	}
	return best, best != ""
}

func levenshteinDistance(left, right string) int {
	leftRunes := []rune(left)
	rightRunes := []rune(right)
	if len(leftRunes) < len(rightRunes) {
		leftRunes, rightRunes = rightRunes, leftRunes
	}
	if len(rightRunes) == 0 {
		return len(leftRunes)
	}

	previous := make([]int, len(rightRunes)+1)
	current := make([]int, len(rightRunes)+1)
	for index := range previous {
		previous[index] = index
	}
	for row, leftRune := range leftRunes {
		current[0] = row + 1
		for column, rightRune := range rightRunes {
			cost := 0
			if leftRune != rightRune {
				cost = 1
			}
			current[column+1] = min(
				current[column]+1,
				previous[column+1]+1,
				previous[column]+cost,
			)
		}
		previous, current = current, previous
	}
	return previous[len(rightRunes)]
}
