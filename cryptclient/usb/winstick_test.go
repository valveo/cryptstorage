package usb

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestRealStickOnWindows needs a real stick; the own-runner workflow sets CRYPTSTORAGE_IT_USB=1.
// It writes and removes the folder .secdisk on the stick and touches nothing else.
func TestRealStickOnWindows(t *testing.T) {
	if runtime.GOOS != "windows" || os.Getenv("CRYPTSTORAGE_IT_USB") != "1" {
		t.Skip("needs Windows and CRYPTSTORAGE_IT_USB=1")
	}
	devs, err := ListRemovable()
	if err != nil || len(devs) == 0 {
		t.Fatalf("no USB disk found: %v", err)
	}
	for _, d := range devs {
		if strings.HasSuffix(d.Path, "PhysicalDrive0") {
			t.Fatalf("the system disk was listed as a stick: %+v", d)
		}
	}
	dev := devs[0]
	t.Logf("stick: %s (%s)", dev.Path, dev.Label)

	root := WindowsMountRoot(dev.Path)
	if root == "" {
		t.Fatal("no drive letter for the stick")
	}
	t.Logf("drive: %s", root)
	defer os.RemoveAll(filepath.Join(root, keyDir))

	if err := CheckRawArea(dev.Path); err != nil {
		t.Fatalf("CheckRawArea: %v", err)
	}
	blob := bytes.Repeat([]byte{0x5a}, 777)
	if err := WriteEncryptedKey(dev.Path, blob); err != nil {
		t.Fatal(err)
	}
	got, err := ReadEncryptedKey(dev.Path)
	if err != nil || !bytes.Equal(got, blob) {
		t.Fatalf("read back: %v", err)
	}
	serial, err := GetSerial(dev.Path)
	if err != nil {
		t.Fatalf("serial: %v", err)
	}
	t.Logf("serial: %s", serial)
	if err := WriteSerialBinding(dev.Path, serial); err != nil {
		t.Fatal(err)
	}
	if err := VerifySerialBinding(dev.Path); err != nil {
		t.Fatalf("binding: %v", err)
	}
	// A binding made for another stick must be refused
	if err := WriteSerialBinding(dev.Path, serial+"-other"); err != nil {
		t.Fatal(err)
	}
	if err := VerifySerialBinding(dev.Path); err == nil {
		t.Fatal("a binding for another serial was accepted")
	}
	found, err := FindCryptDevice()
	if err != nil || found.Path != dev.Path {
		t.Fatalf("FindCryptDevice: %v %+v", err, found)
	}
}
