package aclpolicy //nolint:testpackage // white-box: exercises the unexported looksLikeService/looksLikeSCIMGroup heuristics.

import "testing"

func TestLooksLikeService(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		selector string
		want     bool
	}{
		{name: "service is a service", selector: "svc:my-service", want: true},
		// Recognizing a selector suppresses undefined-reference, so a bare
		// prefix naming nothing must not qualify - the same rule the SCIM
		// heuristic applies to group:@domain and group:name@.
		{name: "bare prefix is not a service", selector: "svc:", want: false},
		{name: "group is not a service", selector: "group:x", want: false},
		{name: "tag is not a service", selector: "tag:web", want: false},
		{name: "empty is not a service", selector: "", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := looksLikeService(tt.selector); got != tt.want {
				t.Errorf("looksLikeService(%q) = %v; want %v", tt.selector, got, tt.want)
			}
		})
	}
}

func TestLooksLikeSCIMGroup(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		selector string
		domains  []string
		want     bool
	}{
		{name: "scim group any domain", selector: "group:x@example.com", want: true},
		{name: "local group has no domain", selector: "group:local", want: false},
		// The exemption suppresses an undefined-reference error, so a selector
		// that is only "@-shaped" must not qualify. Both of these come from a
		// templated policy with one variable unset, and both are hard
		// undefined references rather than synced groups.
		{name: "empty domain is not scim", selector: "group:oops@", want: false},
		{name: "empty name is not scim", selector: "group:@example.com", want: false},
		{name: "bare at is not scim", selector: "group:@", want: false},
		{
			name:     "empty name is not scim even when the domain is listed",
			selector: "group:@example.com",
			domains:  []string{"example.com"},
			want:     false,
		},
		{name: "user is not a group", selector: "alice@example.com", want: false},
		{name: "space in name still scim", selector: "group:team name@example.com", want: true},
		{
			name:     "domain scoped match",
			selector: "group:x@example.com",
			domains:  []string{"example.com"},
			want:     true,
		},
		{
			name:     "domain scoped miss",
			selector: "group:x@other.io",
			domains:  []string{"example.com"},
			want:     false,
		},
		{
			name:     "domain match is case insensitive",
			selector: "group:x@Example.COM",
			domains:  []string{"example.com"},
			want:     true,
		},
		{
			name:     "subdomain of listed domain matches",
			selector: "group:x@eng.example.com",
			domains:  []string{"example.com"},
			want:     true,
		},
		{
			name:     "deep subdomain matches",
			selector: "group:x@a.b.example.com",
			domains:  []string{"example.com"},
			want:     true,
		},
		{
			name:     "leading dot domain form still exact-matches",
			selector: "group:x@example.com",
			domains:  []string{".example.com"},
			want:     true,
		},
		{
			name:     "suffix that is not a subdomain is rejected",
			selector: "group:x@notexample.com",
			domains:  []string{"example.com"},
			want:     false,
		},
		{
			name:     "lookalike suffix after the domain is rejected",
			selector: "group:x@example.com.evil",
			domains:  []string{"example.com"},
			want:     false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := looksLikeSCIMGroup(tt.selector, tt.domains); got != tt.want {
				t.Errorf("looksLikeSCIMGroup(%q, %v) = %v; want %v", tt.selector, tt.domains, got, tt.want)
			}
		})
	}
}
