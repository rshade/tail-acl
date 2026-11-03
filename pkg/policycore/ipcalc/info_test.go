package ipcalc_test

import (
	"net/netip"
	"testing"

	"github.com/rshade/tail-acl/pkg/policycore/ipcalc"
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

func TestInfoIPv6Blocks(t *testing.T) {
	t.Parallel()

	tests := []blockFactsCase{
		{
			name: "slash48", prefix: "2001:db8:1234:5678::/48",
			wantNetwork: "2001:db8:1234::", wantBroadcast: "",
			wantFirst: "2001:db8:1234::", wantLast: "2001:db8:1234:ffff:ffff:ffff:ffff:ffff",
			wantHosts: "1208925819614629174706176",
		},
		{
			name: "slash64_host_bits_masked", prefix: "2001:db8:1::42/64",
			wantNetwork: "2001:db8:1::", wantBroadcast: "",
			wantFirst: "2001:db8:1::", wantLast: "2001:db8:1:0:ffff:ffff:ffff:ffff",
			wantHosts: "18446744073709551616",
		},
		{
			name: "slash96", prefix: "2001:db8:abcd:1234:5678:90ab:cdef:1234/96",
			wantNetwork: "2001:db8:abcd:1234:5678:90ab::", wantBroadcast: "",
			wantFirst: "2001:db8:abcd:1234:5678:90ab::", wantLast: "2001:db8:abcd:1234:5678:90ab:ffff:ffff",
			wantHosts: "4294967296",
		},
		{
			name: "slash127", prefix: "2001:db8::4/127",
			wantNetwork: "2001:db8::4", wantBroadcast: "",
			wantFirst: "2001:db8::4", wantLast: "2001:db8::5", wantHosts: "2",
		},
		{
			name: "slash128", prefix: "2001:db8::1/128",
			wantNetwork: "2001:db8::1", wantBroadcast: "",
			wantFirst: "2001:db8::1", wantLast: "2001:db8::1", wantHosts: "1",
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

func TestInfoRejectsInvalidPrefix(t *testing.T) {
	t.Parallel()

	_, err := ipcalc.Info(netip.Prefix{})
	if err == nil {
		t.Fatal("Info() error = nil, want error for invalid prefix")
	}
}
