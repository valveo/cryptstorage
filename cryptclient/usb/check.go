package usb

import (
	"os"
	"path/filepath"
	"time"
)

// CheckDevice checks directly whether the given device path carries a raw key (a stick prepared on
// Linux by an older version). Used in the udev trigger, which runs before any file system is mounted;
// sticks with the key in their .secdisk folder are recognised by AutoDevice instead.
func CheckDevice(devicePath string) (bool, error) {
	return hasRawMagic(devicePath)
}

// AutoDevice decides, for the user service the udev rule starts when a stick is plugged in, which
// stick to open: devicePath is the disk (a raw key, checked by the rule) or one of its partitions (any
// USB stick with a file system). A partition is followed to its disk once the desktop has mounted it
// and only if the key folder is there; a disk with a raw key is left to the service started for the
// disk itself. ok false: not a CryptStorage stick, or not this service's to open.
func AutoDevice(devicePath string, wait time.Duration) (disk string, ok bool) {
	name := filepath.Base(devicePath)
	if _, err := os.Stat(filepath.Join("/sys/class/block", name, "partition")); err != nil {
		raw, err := hasRawMagic(devicePath)
		return devicePath, err == nil && raw
	}
	p, err := filepath.EvalSymlinks(filepath.Join("/sys/class/block", name))
	if err != nil {
		return "", false
	}
	disk = "/dev/" + filepath.Base(filepath.Dir(p))
	if raw, err := hasRawMagic(disk); err == nil && raw {
		return "", false
	}
	for deadline := time.Now().Add(wait); ; time.Sleep(500 * time.Millisecond) {
		if ok, _ := fileHasKey(disk); ok {
			return disk, true
		}
		if time.Now().After(deadline) {
			return "", false
		}
	}
}
