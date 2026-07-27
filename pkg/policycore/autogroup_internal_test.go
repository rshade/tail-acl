package policycore

import (
	"testing"

	tailscale "tailscale.com/client/tailscale/v2"
)

// TestRoleMatchesRejectsEmptyRole guards against a regression the reviewer
// caught: tailscale.UserRole is a plain string type, so Roles[query] returns
// "" for any login absent from the roster. Without an explicit empty-role
// check, roleMatches("", query) would return true for every such login
// instead of false.
func TestRoleMatchesRejectsEmptyRole(t *testing.T) {
	t.Parallel()

	m := Matcher{
		HaveRoles: true,
		Roles:     map[string]tailscale.UserRole{"bob@example.com": tailscale.UserRoleAdmin},
	}
	if got := m.roleMatches("", "ada@example.com"); got {
		t.Errorf(`roleMatches("", "ada@example.com") = true, want false`)
	}
}

// TestMatchSpecRejectsMalformedDescriptor proves that an autogroupSpec with
// neither role nor matches set — a state autogroupSpecFor never produces
// today, but a future half-added case could — reports no match instead of
// panicking. matchSpec is called directly because the real autogroupSpecFor
// switch cannot be coerced into returning a malformed spec.
func TestMatchSpecRejectsMalformedDescriptor(t *testing.T) {
	t.Parallel()

	m := Matcher{}
	if got := m.matchSpec(autogroupSpec{}, "ada@example.com", ""); got {
		t.Errorf("matchSpec(malformed spec) = true, want false")
	}
}
