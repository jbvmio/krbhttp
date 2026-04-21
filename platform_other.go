//go:build !linux

package krbhttp

// applyPlatformConfig is a no-op on non-Linux platforms. On macOS and Windows
// the negotiate package uses the OS credential store automatically; no paths
// need to be configured.
func applyPlatformConfig(_ *Options) {}
