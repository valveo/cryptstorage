package main

import (
	"os"
	"runtime"
	"testing"
)

func TestRememberUsername(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir) // Linux
	t.Setenv("HOME", dir)            // macOS
	t.Setenv("AppData", dir)         // Windows
	if got := savedUsername(); got != "" {
		t.Fatalf("nothing saved yet, got %q", got)
	}
	rememberUsername("matti")
	if got := savedUsername(); got != "matti" {
		t.Fatalf("got %q", got)
	}
	if runtime.GOOS != "windows" {
		fi, err := os.Stat(usernameFile())
		if err != nil || fi.Mode().Perm() != 0o600 {
			t.Fatalf("file mode %v, %v", fi.Mode(), err)
		}
	}
	rememberUsername("")
	if got := savedUsername(); got != "matti" {
		t.Fatalf("an empty name replaced the saved one: %q", got)
	}
}
