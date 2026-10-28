package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestHostSetRejectsNonAddress(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name, address string
	}{
		{name: "alias", address: "b"},
		{name: "tag", address: "tag:web"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "acl.hujson")
			const before = "{}\n"
			writeTestPolicy(t, path, before)
			_, err := runTailACL(t, path, "host", "set", "a", test.address)
			if err == nil {
				t.Fatal("host set accepted a non-address")
			}
			if code := exitCode(err); code != exitUsage {
				t.Fatalf("exit = %d, want %d (%v)", code, exitUsage, err)
			}
			if !strings.Contains(err.Error(), test.address) || !strings.Contains(err.Error(), "not an address") {
				t.Fatalf("error = %v, want it to name %s as not an address", err, test.address)
			}
			if got := readPolicy(t, path); got != before {
				t.Fatalf("file changed:\n%s", got)
			}
		})
	}
}

func TestHostSetAcceptsLiteralAddressAndPrefix(t *testing.T) {
	t.Parallel()
	for _, address := range []string{"100.64.0.10", "10.1.0.0/16"} {
		t.Run(address, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "acl.hujson")
			writeTestPolicy(t, path, "{}\n")
			if _, err := runTailACL(t, path, "host", "set", "web", address); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(readPolicy(t, path), address) {
				t.Fatalf("policy does not contain %s:\n%s", address, readPolicy(t, path))
			}
		})
	}
}
