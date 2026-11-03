package buildinfo_test

import (
	"strings"
	"testing"

	"github.com/rshade/tsacl/internal/buildinfo"
)

func TestVersionCarriesToolAndReleaseString(t *testing.T) {
	t.Parallel()
	got := buildinfo.Version("tsacl", "v1.2.3")
	if !strings.HasPrefix(got, "tsacl v1.2.3") {
		t.Errorf("Version() = %q, want a \"tsacl v1.2.3\" prefix", got)
	}
}

func TestVersionFallsBackToDev(t *testing.T) {
	t.Parallel()
	got := buildinfo.Version("acl-upload", "dev")
	if !strings.HasPrefix(got, "acl-upload dev") {
		t.Errorf("Version() = %q, want an \"acl-upload dev\" prefix", got)
	}
}
