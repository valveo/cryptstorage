package e2ee

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// Runs only where cppcryptfs and Dokan are installed (the Windows CI job installs them).
func TestWindowsVolumeRoundTrip(t *testing.T) {
	if runtime.GOOS != "windows" || !CppcryptfsInstalled() || !DokanInstalled() {
		t.Skip("needs Windows with cppcryptfs and Dokan")
	}
	pass := []byte("a-derived-volume-passphrase")
	mk, err := NewMasterKey()
	if err != nil {
		t.Fatal(err)
	}
	conf, err := MakeConf(mk, pass, 10)
	if err != nil {
		t.Fatal(err)
	}
	cipher := t.TempDir()
	if err := WriteVolumeFiles(cipher, conf, make([]byte, 16)); err != nil {
		t.Fatal(err)
	}

	// 1. normal unlock with the passphrase, write the canary, read it back
	plain := mkEmptyDir(t)
	if err := MountVolume(cipher, plain, pass); err != nil {
		t.Fatalf("mount: %v", err)
	}
	if err := WriteCanary(plain); err != nil {
		t.Fatal(err)
	}
	if err := CheckCanary(plain); err != nil {
		t.Fatal(err)
	}
	if err := UnmountVolume(plain); err != nil {
		t.Fatalf("unmount: %v", err)
	}

	// 2. a wrong passphrase is reported as such
	plain2 := mkEmptyDir(t)
	err = MountVolume(cipher, plain2, []byte("not the passphrase"))
	if !errors.Is(err, ErrWrongPassphrase) {
		t.Fatalf("wrong passphrase: got %v", err)
	}

	// 3. recovery path: read-only mount with the master key sees the same canary
	plain3 := mkEmptyDir(t)
	if err := MountVolumeWithMasterKey(cipher, plain3, mk, true); err != nil {
		t.Fatalf("master key mount: %v", err)
	}
	if err := CheckCanary(plain3); err != nil {
		t.Fatal(err)
	}
	if err := UnmountVolume(plain3); err != nil {
		t.Fatal(err)
	}
}

func mkEmptyDir(t *testing.T) string {
	d := filepath.Join(t.TempDir(), "mnt")
	if err := os.Mkdir(d, 0o700); err != nil {
		t.Fatal(err)
	}
	return d
}
