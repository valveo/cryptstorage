package main

import (
	"os"
	"testing"
)

// CryptStorage.exe starts the tray with no command, and its menu asks syncDir; that crashed the tray.
func TestSyncDirWithoutCommand(t *testing.T) {
	t.Setenv("CRYPTCLIENT_SYNC_DIR", "")
	saved := os.Args
	defer func() { os.Args = saved }()

	os.Args = []string{"CryptStorage.exe"}
	if d := syncDir(); d != "" {
		t.Fatalf("no command, no syncing: got %q", d)
	}
	os.Args = []string{"cryptclient", "connect"}
	if d := syncDir(); d != "" {
		t.Fatalf("connect without --sync: got %q", d)
	}
	os.Args = []string{"cryptclient", "connect", "--sync"}
	if d := syncDir(); d == "" {
		t.Fatal("connect --sync must turn syncing on")
	}
}
