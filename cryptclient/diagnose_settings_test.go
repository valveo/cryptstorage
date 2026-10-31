package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLegacySettingsAndSource(t *testing.T) {
	home := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", home)
	t.Setenv("HOME", home)
	t.Setenv("APPDATA", home)
	if err := os.MkdirAll(filepath.Join(home, "cryptstorage"), 0o700); err != nil {
		t.Fatal(err)
	}
	if got := legacySettings(); got != "" {
		t.Fatalf("no old folder yet, got %q", got)
	}
	if err := os.MkdirAll(filepath.Join(home, "secdisk"), 0o700); err != nil {
		t.Fatal(err)
	}
	if got := legacySettings(); got != filepath.Join(home, "secdisk") {
		t.Fatalf("old folder not reported: %q", got)
	}
	saved := startEnv
	defer func() { startEnv = saved }()
	startEnv = map[string]bool{}
	if got := settingSource("CRYPTSTORAGE_SERVER"); got != filepath.Join(home, "cryptstorage", "env") {
		t.Fatalf("source = %q", got)
	}
	startEnv["CRYPTSTORAGE_SERVER"] = true
	if got := settingSource("CRYPTSTORAGE_SERVER"); !strings.Contains(got, "environment variable") {
		t.Fatalf("source = %q", got)
	}
}
