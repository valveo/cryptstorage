package appdir

import (
	"os"
	"path/filepath"
	"testing"
)

func TestInNew(t *testing.T) {
	base := t.TempDir()
	if got, want := In(base), filepath.Join(base, Name); got != want {
		t.Fatalf("In = %s, want %s", got, want)
	}
	if _, err := os.Stat(filepath.Join(base, Name)); !os.IsNotExist(err) {
		t.Fatal("In must not create the folder")
	}
}

func TestInMovesLegacy(t *testing.T) {
	base := t.TempDir()
	old := filepath.Join(base, Legacy)
	if err := os.MkdirAll(old, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(old, "username"), []byte("alice\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	dir := In(base)
	if dir != filepath.Join(base, Name) {
		t.Fatalf("In = %s", dir)
	}
	b, err := os.ReadFile(filepath.Join(dir, "username"))
	if err != nil || string(b) != "alice\n" {
		t.Fatalf("username not moved: %q %v", b, err)
	}
	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Fatal("the old folder is still there")
	}
}

func TestInPrefersNew(t *testing.T) {
	base := t.TempDir()
	for _, n := range []string{Name, Legacy} {
		if err := os.MkdirAll(filepath.Join(base, n), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if got := In(base); got != filepath.Join(base, Name) {
		t.Fatalf("In = %s", got)
	}
	if _, err := os.Stat(filepath.Join(base, Legacy)); err != nil {
		t.Fatal("the old folder must be left alone when the new one exists")
	}
}
