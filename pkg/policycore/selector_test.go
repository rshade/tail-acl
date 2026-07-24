package policycore_test

import (
	"testing"

	"github.com/rshade/tailscale-utils/policycore"

	tailscale "tailscale.com/client/tailscale/v2"
)

func TestSelectorMatches(t *testing.T) {
	t.Parallel()

	policy := &tailscale.ACL{
		Groups: map[string][]string{
			"group:eng":   {"alice@example.com", "group:ops"},
			"group:ops":   {"bob@example.com"},
			"group:cycle": {"group:cycle"},
		},
		Hosts: map[string]string{"web": "10.1.0.0/16"},
	}
	tests := []struct {
		name     string
		selector string
		query    string
		source   string
		want     bool
	}{
		{name: "wildcard matches anything", selector: "*", query: "tag:web", want: true},
		{name: "exact tag match", selector: "tag:web", query: "tag:web", want: true},
		{name: "different tag", selector: "tag:web", query: "tag:db", want: false},
		{name: "direct group member", selector: "group:eng", query: "alice@example.com", want: true},
		{name: "nested group member", selector: "group:eng", query: "bob@example.com", want: true},
		{name: "non member", selector: "group:eng", query: "eve@example.com", want: false},
		{name: "cyclic group terminates", selector: "group:cycle", query: "eve@example.com", want: false},
		{name: "autogroup:member matches user", selector: "autogroup:member", query: "alice@example.com", want: true},
		{name: "autogroup:member ignores tag", selector: "autogroup:member", query: "tag:web", want: false},
		{
			name:     "autogroup:self matches source user",
			selector: "autogroup:self",
			query:    "alice@example.com",
			source:   "alice@example.com",
			want:     true,
		},
		{
			name:     "autogroup:self rejects other user",
			selector: "autogroup:self",
			query:    "alice@example.com",
			source:   "bob@example.com",
			want:     false,
		},
		{
			name:     "autogroup:internet matches public address",
			selector: "autogroup:internet",
			query:    "8.8.8.8",
			want:     true,
		},
		{
			name:     "autogroup:internet rejects private address",
			selector: "autogroup:internet",
			query:    "10.1.2.3",
			want:     false,
		},
		{
			name:     "autogroup:tagged matches a tagged device",
			selector: "autogroup:tagged",
			query:    "tag:web",
			want:     true,
		},
		{
			name:     "autogroup:tagged rejects a user",
			selector: "autogroup:tagged",
			query:    "alice@example.com",
			want:     false,
		},
		{name: "host selector contains address", selector: "web", query: "10.1.2.3", want: true},
		{name: "host selector excludes outside address", selector: "web", query: "10.9.2.3", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := policycore.SelectorMatches(tt.selector, tt.query, policy, tt.source)
			if got != tt.want {
				t.Errorf("SelectorMatches(%q, %q) = %v; want %v", tt.selector, tt.query, got, tt.want)
			}
		})
	}
}

func TestAnySelectorMatches(t *testing.T) {
	t.Parallel()

	policy := &tailscale.ACL{}
	if !policycore.AnySelectorMatches([]string{"tag:db", "tag:web"}, "tag:web", policy, "") {
		t.Error("AnySelectorMatches: want true when one selector matches")
	}
	if policycore.AnySelectorMatches([]string{"tag:db"}, "tag:web", policy, "") {
		t.Error("AnySelectorMatches: want false when no selector matches")
	}
	if policycore.AnySelectorMatches(nil, "tag:web", policy, "") {
		t.Error("AnySelectorMatches(nil): want false")
	}
}

func TestLooksLikeUser(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		value string
		want  bool
	}{
		{name: "email is a user", value: "alice@example.com", want: true},
		{name: "group is not a user", value: "group:eng@example.com", want: false},
		{name: "tag is not a user", value: "tag:web", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := policycore.LooksLikeUser(tt.value); got != tt.want {
				t.Errorf("LooksLikeUser(%q) = %v; want %v", tt.value, got, tt.want)
			}
		})
	}
}
