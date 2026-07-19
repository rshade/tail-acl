package buildinfo_test

import (
	"strings"
	"testing"

	"github.com/rshade/tailscale-utils/tail-acl/internal/buildinfo"
)

func TestVersionCarriesToolAndReleaseString(t *testing.T) {
	t.Parallel()
	got := buildinfo.Version("tail-acl", "v1.2.3")
	if !strings.HasPrefix(got, "tail-acl v1.2.3") {
		t.Errorf("Version() = %q, want a \"tail-acl v1.2.3\" prefix", got)
	}
}

func TestVersionFallsBackToDev(t *testing.T) {
	t.Parallel()
	got := buildinfo.Version("acl-upload", "dev")
	if !strings.HasPrefix(got, "acl-upload dev") {
		t.Errorf("Version() = %q, want an \"acl-upload dev\" prefix", got)
	}
}
