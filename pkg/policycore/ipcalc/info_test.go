package ipcalc_test

import (
	"errors"
	"net/netip"
	"testing"

	"github.com/rshade/tailscale-utils/policycore/ipcalc"
)

type blockFactsCase struct {
	name          string
	prefix        string
	wantNetwork   string
	wantBroadcast string // empty means the block has no broadcast address
	wantFirst     string
	wantLast      string
	wantHosts     string
}

func assertBlockFacts(t *testing.T, info ipcalc.BlockInfo, tt blockFactsCase) {
	t.Helper()

	if info.Network.String() != tt.wantNetwork {
		t.Errorf("Info() Network = %v, want %v", info.Network, tt.wantNetwork)
	}
	switch {
	case tt.wantBroadcast == "":
		if info.Broadcast.IsValid() {
			t.Errorf("Info() Broadcast = %v, want none (zero Addr)", info.Broadcast)
		}
	case info.Broadcast.String() != tt.wantBroadcast:
		t.Errorf("Info() Broadcast = %v, want %v", info.Broadcast, tt.wantBroadcast)
	}
	if info.FirstUsable.String() != tt.wantFirst {
		t.Errorf("Info() FirstUsable = %v, want %v", info.FirstUsable, tt.wantFirst)
	}
	if info.LastUsable.String() != tt.wantLast {
		t.Errorf("Info() LastUsable = %v, want %v", info.LastUsable, tt.wantLast)
	}
	if info.UsableHosts.String() != tt.wantHosts {
		t.Errorf("Info() UsableHosts = %s, want %s", info.UsableHosts, tt.wantHosts)
	}
}

func TestInfoIPv4Blocks(t *testing.T) {
	t.Parallel()

	tests := []blockFactsCase{
		{
			name:        "slash8",
			prefix:      "10.0.0.0/8",
			wantNetwork: "10.0.0.0", wantBroadcast: "10.255.255.255",
			wantFirst: "10.0.0.1", wantLast: "10.255.255.254",
			wantHosts: "16777214",
		},
		{
			name:        "slash16",
			prefix:      "192.168.0.0/16",
			wantNetwork: "192.168.0.0", wantBroadcast: "192.168.255.255",
			wantFirst: "192.168.0.1", wantLast: "192.168.255.254",
			wantHosts: "65534",
		},
		{
			name:        "slash24",
			prefix:      "192.168.1.0/24",
			wantNetwork: "192.168.1.0", wantBroadcast: "192.168.1.255",
			wantFirst: "192.168.1.1", wantLast: "192.168.1.254",
			wantHosts: "254",
		},
		{
			name:        "slash30",
			prefix:      "10.1.2.0/30",
			wantNetwork: "10.1.2.0", wantBroadcast: "10.1.2.3",
			wantFirst: "10.1.2.1", wantLast: "10.1.2.2",
			wantHosts: "2",
		},
		{
			name:        "slash31_rfc3021_point_to_point",
			prefix:      "10.0.0.0/31",
			wantNetwork: "10.0.0.0", wantBroadcast: "",
			wantFirst: "10.0.0.0", wantLast: "10.0.0.1",
			wantHosts: "2",
		},
		{
			name:        "slash32_host_route",
			prefix:      "10.0.0.5/32",
			wantNetwork: "10.0.0.5", wantBroadcast: "",
			wantFirst: "10.0.0.5", wantLast: "10.0.0.5",
			wantHosts: "1",
		},
		{
			name:        "host_bits_masked_to_containing_block",
			prefix:      "192.168.1.37/24",
			wantNetwork: "192.168.1.0", wantBroadcast: "192.168.1.255",
			wantFirst: "192.168.1.1", wantLast: "192.168.1.254",
			wantHosts: "254",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			prefix, err := netip.ParsePrefix(tt.prefix)
			if err != nil {
				t.Fatalf("parse prefix %q: %v", tt.prefix, err)
			}

			info, err := ipcalc.Info(prefix)
			if err != nil {
				t.Fatalf("Info() error = %v", err)
			}

			assertBlockFacts(t, info, tt)
		})
	}
}

func TestInfoRejectsIPv6(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		prefix string
	}{
		{name: "native_ipv6", prefix: "2001:db8::/64"},
		{name: "ipv6_full_length", prefix: "fd7a:115c:a1e0::1/128"},
		// Info takes plain IPv4 only; unmapping 4-in-6 input is the
		// caller's job (ipcalc.Unmap4In6), so a raw mapped prefix is
		// rejected like any other IPv6 prefix.
		{name: "unmapped_4in6", prefix: "::ffff:10.0.0.0/120"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			prefix, err := netip.ParsePrefix(tt.prefix)
			if err != nil {
				t.Fatalf("parse prefix %q: %v", tt.prefix, err)
			}

			_, err = ipcalc.Info(prefix)
			if !errors.Is(err, ipcalc.ErrIPv6NotSupported) {
				t.Fatalf("Info() error = %v, want ErrIPv6NotSupported", err)
			}
		})
	}
}

func TestInfoRejectsInvalidPrefix(t *testing.T) {
	t.Parallel()

	_, err := ipcalc.Info(netip.Prefix{})
	if err == nil {
		t.Fatal("Info() error = nil, want error for invalid prefix")
	}
	if errors.Is(err, ipcalc.ErrIPv6NotSupported) {
		t.Fatalf("Info() error = %v, want a plain invalid-prefix error, not ErrIPv6NotSupported", err)
	}
}
