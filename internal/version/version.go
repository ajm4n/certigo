// Package version exposes the build-stamped version string for certigo.
//
// The value is overridden at build time via:
//
//	go build -ldflags "-X github.com/ajm4n/certigo/internal/version.Version=vX.Y.Z"
package version

// Version is the current certigo version. Default "dev" is replaced at
// build time by the Makefile, CI, or goreleaser via -ldflags.
var Version = "dev"
