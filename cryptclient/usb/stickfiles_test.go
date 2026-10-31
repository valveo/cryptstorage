package usb

import (
	"bytes"
	"runtime"
	"testing"
)

func TestWindowsFileStorage(t *testing.T) {
	root := t.TempDir()
	old := fileRoot
	fileRoot = func(string) (string, error) { return root, nil }
	defer func() { fileRoot = old }()
	dev := `\\.\PhysicalDrive7`

	if ok, err := fileHasKey(dev); ok || err != nil {
		t.Fatalf("empty stick: %v %v", ok, err)
	}
	blob := bytes.Repeat([]byte{7}, 300)
	if err := fileWriteKey(dev, blob); err != nil {
		t.Fatal(err)
	}
	if ok, _ := fileHasKey(dev); !ok {
		t.Fatal("key not found after writing")
	}
	got, err := fileReadKey(dev)
	if err != nil || !bytes.Equal(got, blob) {
		t.Fatalf("round trip: %v", err)
	}
	blob2 := bytes.Repeat([]byte{9}, 100)
	if err := fileWriteKey(dev, blob2); err != nil {
		t.Fatal(err)
	}
	if got, _ := fileReadKey(dev); !bytes.Equal(got, blob2) {
		t.Fatal("overwrite failed")
	}
	if err := fileWriteKey(dev, make([]byte, KeySize+1)); err == nil {
		t.Fatal("too large blob accepted")
	}
	h, first, _ := fileStoredBinding(dev)
	if first || len(h) != SerialHashLen || !fileSameBinding(h, make([]byte, SerialHashLen)) {
		t.Fatal("unbound stick should read as zeros")
	}
	want := ComputeSerialHash("ABC")
	if err := fileWriteBinding(dev, want); err != nil {
		t.Fatal(err)
	}
	if h, first, _ := fileStoredBinding(dev); first || !fileSameBinding(h, want) {
		t.Fatal("binding round trip")
	}
}

// A stick bound on another OS family is bound here at its first use; its own binding is never
// replaced by one from elsewhere.
func TestBindingFromAnotherOS(t *testing.T) {
	root := t.TempDir()
	old := fileRoot
	fileRoot = func(string) (string, error) { return root, nil }
	defer func() { fileRoot = old }()
	dev := "/dev/sdz"

	other := "windows"
	if runtime.GOOS == "windows" {
		other = "linux"
	}
	if err := fileWrite(dev, bindingFile(other), ComputeSerialHash("SEEN-THERE")); err != nil {
		t.Fatal(err)
	}
	if _, first, err := fileStoredBinding(dev); !first || err != nil {
		t.Fatalf("a stick bound only on %s should be a first use here: %v %v", other, first, err)
	}
	mine := ComputeSerialHash("SEEN-HERE")
	if err := fileWriteBinding(dev, mine); err != nil {
		t.Fatal(err)
	}
	if h, first, _ := fileStoredBinding(dev); first || !fileSameBinding(h, mine) {
		t.Fatal("this OS's own binding should be used once it exists")
	}
	if bindingFile("windows") != "serial.bin" || bindingFile("linux") != "serial-linux.bin" {
		t.Fatal("binding file names changed: sticks already in use would lose their binding")
	}
}

func TestWinDiskNumber(t *testing.T) {
	if n, err := winDiskNumber(`\\.\PhysicalDrive12`); err != nil || n != 12 {
		t.Fatal(n, err)
	}
	if _, err := winDiskNumber(`/dev/sdb`); err == nil {
		t.Fatal("accepted a non-windows path")
	}
}
