package sshconn

import (
	"os"
	"testing"
)

func TestUnmountedStickKeepsHostKeysInMemoryOnly(t *testing.T) {
	dir := t.TempDir()
	wd, _ := os.Getwd()
	defer os.Chdir(wd)
	os.Chdir(dir)

	m := NewHostKeyManager("")
	if m.Persistent() {
		t.Fatal("no mount path must mean no file")
	}
	m.stored["example.org"] = &StoredHostKey{Hostname: "example.org", KeyType: "ssh-ed25519"}
	if err := m.Load(); err != nil {
		t.Fatal(err)
	}
	if err := m.Save(); err != nil {
		t.Fatal(err)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Fatalf("wrote %v; nothing may be written outside the stick", entries)
	}
	if _, err := os.Stat("/" + HostKeyFile); err == nil {
		t.Fatal("wrote to the root directory")
	}
}
