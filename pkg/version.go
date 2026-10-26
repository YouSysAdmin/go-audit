// Package pkg owns build-time identity (binary name and version string).
// Version is a var so the build can override it via:
//
//	-ldflags "-X github.com/yousysadmin/go-audit/pkg.Version=SOMEVERSION"
package pkg

// AppName is the binary name, used as the syslog tag default and in CLI output.
const AppName = "go-audit"

// Version is "devel" in a plain `go build` and the release tag in a release.
var Version = "devel"
