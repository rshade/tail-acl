package policycore

// EffectiveSrcPosture resolves the source-posture list that gates a rule:
// the rule's own srcPosture when that list is non-empty, otherwise the
// policy's defaultSrcPosture. Tailscale documents the default as replaced
// by a rule's own posture, not added to it, so a rule with its own
// srcPosture is gated by exactly that list.
//
// fromDefault reports whether the returned list came from the fallback, so
// a caller can name the origin of a gate in its decision text.
func EffectiveSrcPosture(own, fallback []string) ([]string, bool) {
	if len(own) != 0 {
		return own, false
	}
	if len(fallback) != 0 {
		return fallback, true
	}
	return nil, false
}
