package policycore_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/rshade/tail-acl/pkg/policycore"
)

func TestParseIPSetMemberAcceptsEveryForm(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		raw  string
		want policycore.IPSetMember
	}{
		{
			name: "cidr is masked",
			raw:  "10.1.2.3/8",
			want: policycore.IPSetMember{Kind: policycore.IPSetMemberPrefix, Target: "10.0.0.0/8"},
		},
		{
			name: "bare address is canonical and not promoted",
			raw:  "2001:DB8::1",
			want: policycore.IPSetMember{Kind: policycore.IPSetMemberPrefix, Target: "2001:db8::1"},
		},
		{
			name: "range keeps its ends",
			raw:  "10.0.0.1-10.0.0.9",
			want: policycore.IPSetMember{Kind: policycore.IPSetMemberRange, Target: "10.0.0.1-10.0.0.9"},
		},
		{
			name: "range ends are canonicalized",
			raw:  "2001:DB8::1-2001:db8:0::9",
			want: policycore.IPSetMember{Kind: policycore.IPSetMemberRange, Target: "2001:db8::1-2001:db8::9"},
		},
		{
			name: "host alias is kept as written",
			raw:  "host:site-01-gw",
			want: policycore.IPSetMember{Kind: policycore.IPSetMemberHost, Target: "host:site-01-gw"},
		},
		{
			name: "ipset reference is kept as written",
			raw:  "ipset:role-users",
			want: policycore.IPSetMember{Kind: policycore.IPSetMemberIPSet, Target: "ipset:role-users"},
		},
		{
			name: "add wraps a reference",
			raw:  "add ipset:role-users",
			want: policycore.IPSetMember{
				Operation: policycore.IPSetAdd, Kind: policycore.IPSetMemberIPSet, Target: "ipset:role-users",
			},
		},
		{
			name: "remove wraps a cidr and collapses whitespace",
			raw:  "  remove   10.1.2.3/16 ",
			want: policycore.IPSetMember{
				Operation: policycore.IPSetRemove, Kind: policycore.IPSetMemberPrefix, Target: "10.1.0.0/16",
			},
		},
		{
			name: "add wraps a range",
			raw:  "add 198.51.100.2-198.51.100.3",
			want: policycore.IPSetMember{
				Operation: policycore.IPSetAdd, Kind: policycore.IPSetMemberRange, Target: "198.51.100.2-198.51.100.3",
			},
		},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			got, err := policycore.ParseIPSetMember(testCase.raw)
			if err != nil {
				t.Fatalf("ParseIPSetMember(%q) = %v", testCase.raw, err)
			}
			if got != testCase.want {
				t.Errorf("ParseIPSetMember(%q) = %#v; want %#v", testCase.raw, got, testCase.want)
			}
		})
	}
}

func TestIPSetMemberStringRendersCanonically(t *testing.T) {
	t.Parallel()

	for raw, want := range map[string]string{
		"10.1.2.3/8":              "10.0.0.0/8",
		"add  host:gw":            "add host:gw",
		"remove 10.1.2.3/16":      "remove 10.1.0.0/16",
		"ipset:base":              "ipset:base",
		"2001:DB8::1-2001:DB8::9": "2001:db8::1-2001:db8::9",
	} {
		member, err := policycore.ParseIPSetMember(raw)
		if err != nil {
			t.Fatalf("ParseIPSetMember(%q) = %v", raw, err)
		}
		if got := member.String(); got != want {
			t.Errorf("ParseIPSetMember(%q).String() = %q; want %q", raw, got, want)
		}
	}
}

func TestIPSetMemberHostAlias(t *testing.T) {
	t.Parallel()

	for raw, want := range map[string]string{
		"host:gw":        "gw",
		"remove host:gw": "gw",
		"ipset:gw":       "",
		"10.0.0.0/8":     "",
	} {
		member, err := policycore.ParseIPSetMember(raw)
		if err != nil {
			t.Fatalf("ParseIPSetMember(%q) = %v", raw, err)
		}
		alias, ok := member.HostAlias()
		if alias != want || ok != (want != "") {
			t.Errorf("ParseIPSetMember(%q).HostAlias() = %q, %t; want %q, %t", raw, alias, ok, want, want != "")
		}
	}
}

func TestParseIPSetMemberRejections(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		raw  string
		want string
	}{
		{"empty", "   ", "must not be empty"},
		{"unknown operation", "drop 10.0.0.0/8", `unsupported operation "drop"`},
		{"three fields", "add 10.0.0.0/8 extra", "is not a member or an add/remove operation"},
		{"operation without target", "add", "is not an address"},
		{"uppercase operation", "Add 10.0.0.0/8", `unsupported operation "Add"`},
		{"range start after end", "10.0.0.9-10.0.0.1", "starts after it ends"},
		{"range mixes families", "10.0.0.1-2001:db8::9", "same family"},
		{"range with a bad end", "10.0.0.1-gateway", "is not an address"},
		{"zoned address", "fe80::1%eth0", "is not an address"},
		{"zoned range end", "fe80::1-fe80::9%eth0", "is not an address"},
		{"empty host alias", "host:", "has no alias after the host: prefix"},
		{"empty ipset name", "ipset:", "has no name after the ipset: prefix"},
		{"hostname", "gateway", "is not an address, CIDR prefix, address range, host: alias, or ipset: reference"},
		{"autogroup", "autogroup:internet", "is not an address"},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			_, err := policycore.ParseIPSetMember(testCase.raw)
			if err == nil {
				t.Fatalf("ParseIPSetMember(%q) succeeded, want an error containing %q", testCase.raw, testCase.want)
			}
			if !strings.Contains(err.Error(), testCase.want) {
				t.Errorf("ParseIPSetMember(%q) = %q; want it to contain %q", testCase.raw, err, testCase.want)
			}
		})
	}
}

func TestValidateIPSetOperations(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		members      []string
		wantImplicit string
		wantRemove   string
	}{
		{name: "empty"},
		{name: "implicit only", members: []string{"ipset:base", "10.0.0.0/8"}},
		{name: "implicit beside add", members: []string{"ipset:base", "add 10.0.0.0/8"}},
		{name: "all explicit", members: []string{"add ipset:base", "remove 10.1.0.0/16"}},
		{
			name:         "implicit before remove",
			members:      []string{"ipset:base", "host:gw", "add 10.0.0.0/8", "remove 10.1.0.0/16"},
			wantImplicit: "ipset:base",
			wantRemove:   "remove 10.1.0.0/16",
		},
		{
			name:         "implicit after remove",
			members:      []string{"remove 10.1.0.0/16", "add 10.0.0.0/8", "10.2.0.0/16"},
			wantImplicit: "10.2.0.0/16",
			wantRemove:   "remove 10.1.0.0/16",
		},
		{
			name:         "malformed member counts as implicit",
			members:      []string{"remove 10.1.0.0/16", "add 10.0.0.0/8 extra"},
			wantImplicit: "add 10.0.0.0/8 extra",
			wantRemove:   "remove 10.1.0.0/16",
		},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			err := policycore.ValidateIPSetOperations(testCase.members)
			if testCase.wantImplicit == "" {
				if err != nil {
					t.Fatalf("ValidateIPSetOperations(%q) = %v; want nil", testCase.members, err)
				}
				return
			}
			var implicit *policycore.IPSetImplicitMemberError
			if !errors.As(err, &implicit) {
				t.Fatalf("ValidateIPSetOperations(%q) = %v; want IPSetImplicitMemberError", testCase.members, err)
			}
			if implicit.Member != testCase.wantImplicit || implicit.Remove != testCase.wantRemove {
				t.Errorf("error = %#v; want member %q and remove %q",
					implicit, testCase.wantImplicit, testCase.wantRemove)
			}
			if want := `"add ` + testCase.wantImplicit + `"`; !strings.Contains(err.Error(), want) {
				t.Errorf("error %q does not tell the operator to write %s", err, want)
			}
		})
	}
}
