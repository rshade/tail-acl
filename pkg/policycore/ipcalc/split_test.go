package ipcalc_test

import (
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/rshade/tsacl/pkg/policycore/ipcalc"
)

func TestUnmap4In6(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		prefix     string
		wantOK     bool
		wantResult string
	}{
		{name: "mapped_v4", prefix: "::ffff:10.0.0.0/120", wantOK: true, wantResult: "10.0.0.0/24"},
		{name: "mapped_v4_full_bits", prefix: "::ffff:10.0.0.5/128", wantOK: true, wantResult: "10.0.0.5/32"},
		{name: "mapped_v4_min_bits", prefix: "::ffff:0.0.0.0/96", wantOK: true, wantResult: "0.0.0.0/0"},
		{name: "too_short", prefix: "::ffff:10.0.0.0/95", wantOK: false},
		{name: "plain_ipv6", prefix: "fd7a:115c:a1e0::/48", wantOK: false},
		{name: "plain_ipv4", prefix: "10.0.0.0/24", wantOK: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			prefix, err := netip.ParsePrefix(tt.prefix)
			if err != nil {
				t.Fatalf("parse prefix %q: %v", tt.prefix, err)
			}

			result, ok := ipcalc.Unmap4In6(prefix)
			if ok != tt.wantOK {
				t.Fatalf("Unmap4In6() ok = %v, want %v", ok, tt.wantOK)
			}
			if ok && result.String() != tt.wantResult {
				t.Errorf("Unmap4In6() result = %v, want %v", result, tt.wantResult)
			}
		})
	}
}

func TestSplitBasic(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		parent     string
		targetBits int
		wantCount  int64
	}{
		{name: "ipv4_16_to_24", parent: "10.0.0.0/16", targetBits: 24, wantCount: 256},
		{name: "target_equals_parent", parent: "10.0.0.0/24", targetBits: 24, wantCount: 1},
		{name: "split_31_to_32", parent: "10.0.0.0/31", targetBits: 32, wantCount: 2},
		{name: "split_32_to_32", parent: "10.0.0.0/32", targetBits: 32, wantCount: 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			parent, err := netip.ParsePrefix(tt.parent)
			if err != nil {
				t.Fatalf("parse parent %q: %v", tt.parent, err)
			}

			children, count, err := ipcalc.Split(parent, tt.targetBits)

			if err != nil {
				t.Fatalf("Split() error = %v", err)
			}

			if count.Int64() != tt.wantCount {
				t.Errorf("Split() count = %d, want %d", count.Int64(), tt.wantCount)
			}

			if int64(len(children)) != tt.wantCount {
				t.Errorf("Split() len(children) = %d, want %d", len(children), tt.wantCount)
			}
		})
	}
}

func TestSplitErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		parent     string
		targetBits int
		wantErrMsg string
	}{
		{
			name:       "target_shorter_than_parent",
			parent:     "10.0.0.0/24",
			targetBits: 16,
			wantErrMsg: "shorter than parent",
		},
		{
			name:       "target_beyond_address_length",
			parent:     "10.0.0.0/16",
			targetBits: 33,
			wantErrMsg: "exceeds address length",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			parent, err := netip.ParsePrefix(tt.parent)
			if err != nil {
				t.Fatalf("parse parent %q: %v", tt.parent, err)
			}

			_, _, err = ipcalc.Split(parent, tt.targetBits)

			if err == nil {
				t.Fatalf("Split() error = nil, want error")
			}

			if !strings.Contains(err.Error(), tt.wantErrMsg) {
				t.Errorf("Split() error = %q, want to contain %q", err, tt.wantErrMsg)
			}
		})
	}
}

func TestSplitIPv4EdgeCases(t *testing.T) {
	t.Parallel()

	// 10.0.0.0/31 into /32s
	parent, _ := netip.ParsePrefix("10.0.0.0/31")
	children, _, err := ipcalc.Split(parent, 32)
	if err != nil {
		t.Fatalf("Split() error = %v", err)
	}
	if len(children) != 2 {
		t.Errorf("len(children) = %d, want 2", len(children))
	}
	if children[0].String() != "10.0.0.0/32" {
		t.Errorf("children[0] = %v, want 10.0.0.0/32", children[0])
	}
	if children[1].String() != "10.0.0.1/32" {
		t.Errorf("children[1] = %v, want 10.0.0.1/32", children[1])
	}
}

func TestSplitIPv6EdgeCases(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		parent     string
		targetBits int
		want       []string
	}{
		{
			name:       "split_127_to_128",
			parent:     "fd7a:115c:a1e0::/127",
			targetBits: 128,
			want: []string{
				"fd7a:115c:a1e0::/128",
				"fd7a:115c:a1e0::1/128",
			},
		},
		{
			name:       "split_128_to_128",
			parent:     "fd7a:115c:a1e0::1/128",
			targetBits: 128,
			want:       []string{"fd7a:115c:a1e0::1/128"},
		},
		{
			name:       "parent_equals_target",
			parent:     "2001:db8:1:2::/64",
			targetBits: 64,
			want:       []string{"2001:db8:1:2::/64"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			parent, err := netip.ParsePrefix(tt.parent)
			if err != nil {
				t.Fatalf("parse parent %q: %v", tt.parent, err)
			}

			children, count, err := ipcalc.Split(parent, tt.targetBits)
			if err != nil {
				t.Fatalf("Split() error = %v", err)
			}
			if count.Int64() != int64(len(tt.want)) {
				t.Errorf("Split() count = %d, want %d", count.Int64(), len(tt.want))
			}
			if len(children) != len(tt.want) {
				t.Fatalf("Split() len(children) = %d, want %d", len(children), len(tt.want))
			}
			for i, want := range tt.want {
				if children[i].String() != want {
					t.Errorf("Split() children[%d] = %v, want %v", i, children[i], want)
				}
			}
		})
	}
}

func TestSplitVerifyAllChildren(t *testing.T) {
	t.Parallel()

	// Verify a complete split: 10.0.0.0/16 into /24s (256 children).
	parent, _ := netip.ParsePrefix("10.0.0.0/16")
	children, count, err := ipcalc.Split(parent, 24)

	if err != nil {
		t.Fatalf("Split() error = %v, want nil", err)
	}

	if count.Int64() != 256 {
		t.Errorf("Split() count = %d, want 256", count.Int64())
	}

	if len(children) != 256 {
		t.Errorf("Split() len(children) = %d, want 256", len(children))
	}

	// Check first, middle, and last child.
	tests := []struct {
		index int
		want  string
	}{
		{0, "10.0.0.0/24"},
		{128, "10.0.128.0/24"},
		{255, "10.0.255.0/24"},
	}

	for _, tt := range tests {
		if children[tt.index].String() != tt.want {
			t.Errorf("children[%d] = %v, want %v", tt.index, children[tt.index], tt.want)
		}
	}
}

func TestSplitMaxMaterialized(t *testing.T) {
	t.Parallel()

	// Test that exceeding MaxMaterializedChildren returns ErrTooManyChildren.
	parent, _ := netip.ParsePrefix("10.0.0.0/8")
	children, count, err := ipcalc.Split(parent, 32)

	if err == nil {
		t.Fatalf("Split() error = nil, want ErrTooManyChildren")
	}

	if !errors.Is(err, ipcalc.ErrTooManyChildren) {
		t.Errorf("Split() error = %v, want ErrTooManyChildren", err)
	}

	if children != nil {
		t.Errorf("Split() children = %v, want nil", children)
	}

	if count.Int64() != 16777216 {
		t.Errorf("Split() count = %d, want 16777216", count.Int64())
	}
}

func TestSplitIPv6MaterializationBoundary(t *testing.T) {
	t.Parallel()

	parent, parseErr := netip.ParsePrefix("2001:db8::/32")
	if parseErr != nil {
		t.Fatalf("parse parent: %v", parseErr)
	}

	t.Run("at_limit_is_materialized", func(t *testing.T) {
		t.Parallel()

		children, count, err := ipcalc.Split(parent, 48)
		if err != nil {
			t.Fatalf("Split() error = %v", err)
		}
		if count.String() != "65536" {
			t.Errorf("Split() count = %s, want 65536", count)
		}
		if len(children) != ipcalc.MaxMaterializedChildren {
			t.Fatalf("Split() len(children) = %d, want %d", len(children), ipcalc.MaxMaterializedChildren)
		}
		if children[0].String() != "2001:db8::/48" {
			t.Errorf("Split() first child = %v, want 2001:db8::/48", children[0])
		}
		if children[len(children)-1].String() != "2001:db8:ffff::/48" {
			t.Errorf("Split() last child = %v, want 2001:db8:ffff::/48", children[len(children)-1])
		}
	})

	t.Run("over_limit_returns_exact_count", func(t *testing.T) {
		t.Parallel()

		children, count, err := ipcalc.Split(parent, 64)
		if !errors.Is(err, ipcalc.ErrTooManyChildren) {
			t.Fatalf("Split() error = %v, want ErrTooManyChildren", err)
		}
		if children != nil {
			t.Errorf("Split() children = %v, want nil", children)
		}
		if count.String() != "4294967296" {
			t.Errorf("Split() count = %s, want 4294967296", count)
		}
	})
}
