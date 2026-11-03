package aclpolicy

import (
	"errors"
	"fmt"
	"strings"
)

const posturePrefix = "posture:"

// NormalizePostureName canonicalizes a posture name for the postures map: a
// bare name is prefixed with "posture:"; a name already carrying that prefix
// is returned unchanged; any other prefix, or an empty name (or the prefix
// alone with no name after it), is rejected. It is shared by "posture set"
// and "posture remove" so both use identical name resolution, and is the
// seam a future dangling-reference lint check (tsacl lint, issue #17)
// should reuse against Grant.SrcPosture values it wants to look up.
func NormalizePostureName(name string) (string, error) {
	if name == "" {
		return "", errors.New("posture name must not be empty")
	}
	if rest, ok := strings.CutPrefix(name, posturePrefix); ok {
		if rest == "" {
			return "", fmt.Errorf("posture name %q is missing a name after %s", name, posturePrefix)
		}
		return name, nil
	}
	if prefix, _, ok := strings.Cut(name, ":"); ok {
		return "", fmt.Errorf("posture name %q must use the %s prefix, not %q", name, posturePrefix, prefix+":")
	}
	return posturePrefix + name, nil
}

// ValidatePostureReference reports whether value has the shape of a posture
// reference usable in Grant.SrcPosture: it must carry the literal "posture:"
// prefix with a non-empty remainder. Unlike NormalizePostureName, it never
// auto-prefixes a bare name — cmd/tsacl's grant add --src-posture flag
// deliberately requires the caller to spell the prefix explicitly, rather
// than silently accepting a bare name the way "posture set" does. It does
// not check whether the posture is actually defined in postures; dangling
// srcPosture references are tsacl lint's job (issue #17), not authoring's.
func ValidatePostureReference(value string) error {
	rest, ok := strings.CutPrefix(value, posturePrefix)
	if !ok || rest == "" {
		return fmt.Errorf("posture reference %q must have the form %sNAME", value, posturePrefix)
	}
	return nil
}
