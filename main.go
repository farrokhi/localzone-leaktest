// Command localzone-leaktest checks whether a DNS resolver keeps queries for the
// IANA locally served zones and special use names local, or leaks them to the
// public internet.
package main

import (
	"os"
	"runtime/debug"

	"github.com/farrokhi/localzone-leaktest/internal/cli"
)

// version is stamped by release builds via -ldflags "-X main.version=vX.Y.Z".
var version = "dev"

func main() {
	os.Exit(cli.Execute(resolveVersion()))
}

// resolveVersion trusts an explicit release stamp first, since the toolchain's
// VCS-derived build info degrades to a pseudo-version on any dirty tree. The
// build info still covers `go install ...@vX.Y.Z` builds, which have no stamp.
func resolveVersion() string {
	if version != "dev" {
		return version
	}
	if info, ok := debug.ReadBuildInfo(); ok {
		if v := info.Main.Version; v != "" && v != "(devel)" {
			return v
		}
	}
	return version
}
