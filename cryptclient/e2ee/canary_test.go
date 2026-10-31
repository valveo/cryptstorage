package e2ee

import (
	"os"
	"path/filepath"
	"testing"
)

// VerifyKey only looks at files, so plain directories stand in for the ciphertext and the mount.
func verifyDirs(t *testing.T) (cipher, plain string) {
	t.Helper()
	cipher, plain = t.TempDir(), t.TempDir()
	for _, n := range []string{"gocryptfs.conf", "gocryptfs.diriv", "gocryptfs.conf.bak"} {
		os.WriteFile(filepath.Join(cipher, n), []byte("x"), 0o600)
	}
	return cipher, plain
}

func TestVerifyKeyWithCanary(t *testing.T) {
	cipher, plain := verifyDirs(t)
	if err := WriteCanary(plain); err != nil {
		t.Fatal(err)
	}
	if err := VerifyKey(cipher, plain); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(plain, CanaryName), []byte("garbage"), 0o600)
	if VerifyKey(cipher, plain) == nil {
		t.Fatal("a check file with the wrong content passed")
	}
}

// The user deleted the check file: a readable file still proves the key.
func TestVerifyKeyWithoutCanaryReadsAFile(t *testing.T) {
	cipher, plain := verifyDirs(t)
	os.WriteFile(filepath.Join(cipher, "Xq3vT1encrypted"), []byte("c"), 0o600)
	os.MkdirAll(filepath.Join(plain, "docs"), 0o700)
	os.WriteFile(filepath.Join(plain, "docs", "empty.txt"), nil, 0o600) // empty files prove nothing
	if VerifyKey(cipher, plain) == nil {
		t.Fatal("passed with no readable non-empty file")
	}
	os.WriteFile(filepath.Join(plain, "docs", "a.txt"), []byte("hello"), 0o600)
	if err := VerifyKey(cipher, plain); err != nil {
		t.Fatalf("a readable file should prove the key: %v", err)
	}
}

// A wrong key decrypts no names: the mount looks empty while the ciphertext is not.
func TestVerifyKeyRefusesEmptyLookingVolumeWithCiphertext(t *testing.T) {
	cipher, plain := verifyDirs(t)
	os.WriteFile(filepath.Join(cipher, "gocryptfs.longname.abc"), []byte("c"), 0o600)
	if VerifyKey(cipher, plain) == nil {
		t.Fatal("an empty-looking mount over real ciphertext passed")
	}
}

// Nothing but the volume's own files (and dot files such as a sync lock): nothing to lose.
func TestVerifyKeyAcceptsEmptyVolume(t *testing.T) {
	cipher, plain := verifyDirs(t)
	os.Mkdir(filepath.Join(cipher, ".lock"), 0o700)
	if err := VerifyKey(cipher, plain); err != nil {
		t.Fatal(err)
	}
}
