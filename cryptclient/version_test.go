package main

import (
	"runtime/debug"
	"testing"
)

func TestDevVersion(t *testing.T) {
	s := func(kv ...string) []debug.BuildSetting {
		var out []debug.BuildSetting
		for i := 0; i < len(kv); i += 2 {
			out = append(out, debug.BuildSetting{Key: kv[i], Value: kv[i+1]})
		}
		return out
	}
	for _, c := range []struct {
		settings []debug.BuildSetting
		want     string
	}{
		{s("vcs.revision", "9151441e6c2391b6ea2ff5c1acd86da1936c0f1", "vcs.time", "2026-10-29T14:38:02Z", "vcs.modified", "false"),
			"dev+9151441 (2026-10-29)"},
		{s("vcs.revision", "9151441e6c", "vcs.time", "2026-10-29T14:38:02Z", "vcs.modified", "true"),
			"dev+9151441-modified (2026-10-29)"},
		{s("GOOS", "linux"), "dev"},
	} {
		if got := devVersion(c.settings); got != c.want {
			t.Errorf("%v: got %q, want %q", c.settings, got, c.want)
		}
	}
}
