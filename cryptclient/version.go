package main

import "runtime/debug"

// appVersion is what the client calls itself: Version for a release build (set by the build script), or
// else the commit and its date that Go records from git at build time, e.g. "dev+9151441 (2026-10-29)",
// the same form the server shows (scripts/version.sh). So every build says which code it is.
func appVersion() string {
	if Version != "dev" {
		return Version
	}
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return Version
	}
	return devVersion(info.Settings)
}

func devVersion(settings []debug.BuildSetting) string {
	var rev, at string
	modified := false
	for _, s := range settings {
		switch s.Key {
		case "vcs.revision":
			rev = s.Value
		case "vcs.time":
			at = s.Value
		case "vcs.modified":
			modified = s.Value == "true"
		}
	}
	if rev == "" {
		return "dev"
	}
	if len(rev) > 7 {
		rev = rev[:7]
	}
	v := "dev+" + rev
	if modified {
		v += "-modified"
	}
	if len(at) >= 10 {
		v += " (" + at[:10] + ")"
	}
	return v
}
