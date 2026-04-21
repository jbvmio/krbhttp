//go:build linux

package krbhttp

import "github.com/jbvmio/krbhttp/negotiate"

// applyPlatformConfig sets ccache and conf paths on Linux.
// These are no-ops on macOS and Windows (see platform_other.go).
func applyPlatformConfig(o *Options) {
	if o.ccachePath != "" {
		negotiate.SetCCachePath(o.ccachePath)
	}
	if o.confPath != "" {
		negotiate.SetConfPath(o.confPath)
	}
}
