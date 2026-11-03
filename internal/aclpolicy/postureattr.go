package aclpolicy

import (
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/rshade/tail-acl/pkg/policycore/posture"
)

// ParsePostureAttr parses one KEY=VALUE posture attribute, the form check's
// --posture-attr flag and (later) test add's --src-posture-attr flag take.
// The key is the attribute name as the policy spells it ("node:os",
// "custom:deviceApproved").
//
// Values are typed the way a posture expression would read them. A VALUE
// that is a JSON bool, number, or double-quoted string is typed accordingly;
// a single-quoted VALUE is the string inside the quotes, matching the
// quoting posture expressions themselves use; anything else is the bare
// string. So flag=true is the boolean true, flag='true' and flag="true" are
// the string "true", flag=5 is the number 5, and flag=nyc is the string
// "nyc". JSON null, objects, and arrays are not posture attribute values and
// fall through to the bare-string reading.
func ParsePostureAttr(spec string) (string, any, error) {
	key, value, found := strings.Cut(spec, "=")
	key = strings.TrimSpace(key)
	if !found || key == "" {
		return "", nil, fmt.Errorf("posture attribute %q must use KEY=VALUE form", spec)
	}
	var typed any
	if err := json.Unmarshal([]byte(value), &typed); err == nil {
		switch typed.(type) {
		case bool, float64, string:
			return key, typed, nil
		}
	}
	const minQuotedLength = 2
	if len(value) >= minQuotedLength && value[0] == '\'' && value[len(value)-1] == '\'' {
		return key, value[1 : len(value)-1], nil
	}
	return key, value, nil
}

// ParsePostureAttrs folds repeated KEY=VALUE flags into one attribute map.
// A repeated key is a usage error rather than a silent override: two values
// for one attribute is an authoring mistake, and picking one would hide it.
func ParsePostureAttrs(specs []string) (map[string]any, error) {
	if len(specs) == 0 {
		//nolint:nilnil // a nil map is the meaningful answer here: it is how the caller tells "no attributes supplied" apart from an asserted-complete empty set.
		return nil, nil
	}
	attrs := make(map[string]any, len(specs))
	for _, spec := range specs {
		key, value, err := ParsePostureAttr(spec)
		if err != nil {
			return nil, err
		}
		if _, duplicate := attrs[key]; duplicate {
			return nil, fmt.Errorf("posture attribute %q is set more than once", key)
		}
		attrs[key] = value
	}
	return attrs, nil
}

// PostureAttrWarnings checks attribute keys against the known-attribute
// vocabulary (policycore/posture's table) and returns one warning string per
// questionable key, sorted for deterministic output. It never returns an
// error: custom: keys are user-defined and pass silently, and an unknown
// node:/ip: key or a namespace-less key only warns — the vocabulary is
// editorial and goes stale, and an authoring command that refuses a key the
// server accepts is worse than one that warns.
func PostureAttrWarnings(attrs map[string]any) []string {
	var warnings []string
	for _, key := range slices.Sorted(maps.Keys(attrs)) {
		// IS SET is the probe form because it parses for an attribute of any
		// type; the bare form would flag known non-boolean attributes.
		for _, diagnostic := range posture.Validate(key + " IS SET") {
			warnings = append(warnings, fmt.Sprintf("posture attribute %q: %s", key, diagnostic.Reason))
			break
		}
	}
	return warnings
}
