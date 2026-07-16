// Command localzone-leaktest checks whether a DNS resolver keeps queries for the
// IANA locally served zones and special use names local, or leaks them to the
// public internet.
package main

import (
	"os"
	"runtime/debug"

	"github.com/farrokhi/localzone-leaktest/internal/cli"
)

// version is the fallback build version. Release builds may override it with
// -ldflags "-X main.version=...", and an install via `go install ...@vX.Y.Z`
// reports that tag automatically through the module build info.
var version = "1.0.0"

func main() {
	os.Exit(cli.Execute(resolveVersion()))
}

// resolveVersion prefers the module version stamped into the binary by the Go
// toolchain (present when installed from a tagged release), falling back to the
// compiled-in default for source builds.
func resolveVersion() string {
	if info, ok := debug.ReadBuildInfo(); ok {
		if v := info.Main.Version; v != "" && v != "(devel)" {
			return v
		}
	}
	return version
}
