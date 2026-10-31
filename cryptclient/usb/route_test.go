package usb

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// A stick with a raw key from an older Linux version stays raw; any other stick keeps its key in the
// .secdisk folder, on every OS. Clearing the raw key moves the stick over for good.
func TestKeyGoesToTheFolderUnlessTheStickHasARawKey(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows always uses the folder")
	}
	root := t.TempDir()
	old := fileRoot
	fileRoot = func(string) (string, error) { return root, nil }
	defer func() { fileRoot = old }()
	img := filepath.Join(t.TempDir(), "stick.img")
	if err := os.WriteFile(img, make([]byte, 4<<20), 0o600); err != nil {
		t.Fatal(err)
	}

	blob := bytes.Repeat([]byte{5}, 300)
	if err := WriteEncryptedKey(img, blob); err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(filepath.Join(root, keyDir, "key.bin")); err != nil || !bytes.Equal(b, blob) {
		t.Fatalf("a new stick's key should be a file: %v", err)
	}
	if raw, _ := hasRawMagic(img); raw {
		t.Fatal("nothing should have been written to the raw sectors")
	}

	// an older stick: magic and key in raw sectors
	f, _ := os.OpenFile(img, os.O_RDWR, 0)
	f.WriteAt(MagicBytes, MagicOffset)       //nolint
	f.WriteAt([]byte{3, 0, 0, 0}, LenOffset) //nolint
	f.WriteAt([]byte{1, 2, 3}, KeyOffset)    //nolint
	f.Close()
	if got, err := ReadEncryptedKey(img); err != nil || !bytes.Equal(got, []byte{1, 2, 3}) {
		t.Fatalf("a stick with a raw key should be read raw: %v %v", got, err)
	}

	if err := clearRawKey(img); err != nil {
		t.Fatal(err)
	}
	if raw, _ := hasRawMagic(img); raw {
		t.Fatal("the raw key was not cleared")
	}
	if got, err := ReadEncryptedKey(img); err != nil || !bytes.Equal(got, blob) {
		t.Fatalf("after clearing, the folder's key should be read: %v", err)
	}
}
