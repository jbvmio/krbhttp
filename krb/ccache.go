package krb

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"
)

const (
	krb5CacheDefaultDir    = "/tmp"
	krb5CacheDefaultPrefix = "krb5cc_"
	krb5ConfDefaultFile    = "/krb5.conf"
	krb5ConfSystemPath     = "/etc/krb5.conf"
)

// ResolveCCachePath returns the ccache FILE path, applying this priority order:
//  1. explicit (non-empty) — type prefix stripped / resolved
//  2. KRB5CCNAME environment variable — type prefix stripped / resolved
//  3. /tmp/krb5cc_<uid> (MIT Kerberos default)
//
// Supported ccache types:
//
//	FILE:/path  → /path
//	/path       → /path (bare path, already a file)
//	DIR:/path   → resolved to the active cache file via the primary pointer
//
// Unsupported types (KEYRING:, KCM:, MEMORY:) return a descriptive error
// explaining how to export to a FILE ccache that gokrb5 can read.
func ResolveCCachePath(explicit string) (string, error) {
	if explicit != "" {
		return resolveCCacheValue(explicit)
	}
	if env := os.Getenv("KRB5CCNAME"); env != "" {
		return resolveCCacheValue(env)
	}
	u, err := user.Current()
	if err != nil {
		return "", fmt.Errorf("resolving ccache default path: cannot determine current user: %w", err)
	}
	return krb5CacheDefaultDir + "/" + krb5CacheDefaultPrefix + u.Uid, nil
}

// resolveCCacheValue resolves a single KRB5CCNAME value to a file path.
func resolveCCacheValue(value string) (string, error) {
	switch {
	case strings.HasPrefix(value, "FILE:"):
		return strings.TrimPrefix(value, "FILE:"), nil

	case strings.HasPrefix(value, "DIR:"):
		dir := strings.TrimPrefix(value, "DIR:")
		return resolveDirCCache(dir)

	case strings.HasPrefix(value, "KEYRING:"):
		return "", fmt.Errorf(
			"ccache type KEYRING is not supported by gokrb5 (value: %q)\n"+
				"Export to a FILE ccache with:\n"+
				"  kinit -c FILE:/tmp/krb5cc_$(id -u) -R   # renew into a file cache\n"+
				"  or: export KRB5CCNAME=FILE:/tmp/krb5cc_$(id -u) && kinit",
			value)

	case strings.HasPrefix(value, "KCM:"):
		return "", fmt.Errorf(
			"ccache type KCM is not supported by gokrb5 (value: %q)\n"+
				"Export to a FILE ccache with:\n"+
				"  export KRB5CCNAME=FILE:/tmp/krb5cc_$(id -u) && kinit",
			value)

	case strings.HasPrefix(value, "MEMORY:"):
		return "", fmt.Errorf(
			"ccache type MEMORY is not supported (value: %q): in-memory caches "+
				"are not accessible across process boundaries",
			value)

	default:
		// Bare path — no prefix. Treat as FILE.
		return value, nil
	}
}

// resolveDirCCache resolves a DIR: ccache directory to the active FILE cache.
// A DIR: ccache is a directory containing individual FILE caches. The active
// cache is named in a file called "primary" inside the directory.
//
//	/tmp/krb5cc.d/           ← DIR: path
//	/tmp/krb5cc.d/primary    ← contains e.g. "tkt12345"
//	/tmp/krb5cc.d/tkt12345   ← the actual FILE ccache
func resolveDirCCache(dir string) (string, error) {
	primaryFile := filepath.Join(dir, "primary")
	data, err := os.ReadFile(primaryFile)
	if err != nil {
		return "", fmt.Errorf("DIR: ccache: reading primary pointer %q: %w", primaryFile, err)
	}
	primary := strings.TrimSpace(string(data))
	if primary == "" {
		return "", fmt.Errorf("DIR: ccache: primary pointer file %q is empty", primaryFile)
	}
	return filepath.Join(dir, primary), nil
}

// ResolveConfPath returns the krb5.conf path, applying this priority order:
//  1. explicit (non-empty)
//  2. KRB5_CONFIG environment variable
//  3. ~/.krb5.conf (if it exists)
//  4. /etc/krb5.conf
//
// Never returns an error; /etc/krb5.conf is returned as fallback and gokrb5
// config.Load will report a meaningful error if the file is missing.
func ResolveConfPath(explicit string) (string, error) {
	if explicit != "" {
		return explicit, nil
	}
	if env := os.Getenv("KRB5_CONFIG"); env != "" {
		return env, nil
	}
	if u, err := user.Current(); err == nil {
		home := u.HomeDir + krb5ConfDefaultFile
		if fileExists(home) {
			return home, nil
		}
	}
	return krb5ConfSystemPath, nil
}

// stripFilePrefix removes the "FILE:" scheme prefix from a ccache path.
func stripFilePrefix(path string) string {
	return strings.TrimPrefix(path, "FILE:")
}

// fileExists reports whether path exists and is not a directory.
func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}
