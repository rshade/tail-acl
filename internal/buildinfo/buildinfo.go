// Package buildinfo formats a tool's version string with embedded VCS
// provenance, so every binary's --version reports exactly what was built.
package buildinfo

import (
	"fmt"
	"runtime/debug"
)

// shortRevLen truncates the embedded VCS revision to a git-style short hash.
const shortRevLen = 12

// Version renders "<tool> <version> (<rev>[+dirty])" using the build-embedded
// VCS revision. version is the ldflags-injected release string (or "dev"); the
// revision and dirty marker come from [debug.ReadBuildInfo], so an audit can
// tie a binary back to an exact commit without trusting the release string
// alone.
func Version(tool, version string) string {
	v := version
	if bi, ok := debug.ReadBuildInfo(); ok {
		var rev, dirty string
		for _, s := range bi.Settings {
			switch s.Key {
			case "vcs.revision":
				rev = s.Value
			case "vcs.modified":
				if s.Value == "true" {
					dirty = "+dirty"
				}
			}
		}
		if len(rev) > shortRevLen {
			rev = rev[:shortRevLen]
		}
		if rev != "" {
			v = fmt.Sprintf("%s (%s%s)", v, rev, dirty)
		}
	}
	return tool + " " + v
}
