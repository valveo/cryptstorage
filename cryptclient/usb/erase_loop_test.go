//go:build linux

package usb

import (
	"os"
	"testing"
)

// TestEraseStickOnLoopDevice runs the real erase on a loop device, as root:
//
//	truncate -s 80M /tmp/stick.img && sudo losetup -fP --show /tmp/stick.img
//	sudo CRYPTCLIENT_ERASE_TEST_DEVICE=/dev/loopN go test ./usb -run EraseStickOnLoop
func TestEraseStickOnLoopDevice(t *testing.T) {
	dev := os.Getenv("CRYPTCLIENT_ERASE_TEST_DEVICE")
	if dev == "" {
		t.Skip("CRYPTCLIENT_ERASE_TEST_DEVICE not set")
	}
	if err := EraseStick(dev); err != nil {
		t.Fatal(err)
	}
	if err := CheckRawArea(dev); err != nil {
		t.Fatalf("key area not free after erasing: %v", err)
	}
	b := make([]byte, 512)
	f, err := os.Open(PartitionPath(dev))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.ReadAt(b, 0); err != nil {
		t.Fatal(err)
	}
	if string(b[82:90]) != "FAT32   " {
		t.Fatalf("the partition is not FAT32: %q", b[82:90])
	}
}
