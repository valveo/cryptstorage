package usb

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// Device represents a detected USB block device.
type Device struct {
	Path  string // e.g. /dev/sdb, \\.\PhysicalDrive1, /dev/rdisk2
	Label string // human-readable name if available
}

// MagicOffset is the sector offset where magic bytes are written.
const MagicOffset = int64(2048) * 512 // sector 2048

// MagicBytes identifies a cryptclient-formatted USB stick.
var MagicBytes = []byte{0x43, 0x52, 0x59, 0x50, 0x54, 0x4B, 0x45, 0x59} // "CRYPTKEY"

// FindCryptDevice scans available block devices and returns the first one that carries a key: in
// the stick's .secdisk folder, or (a stick prepared on Linux by an older version) in raw sectors.
func FindCryptDevice() (*Device, error) {
	candidates, err := listCandidates()
	if err != nil {
		return nil, fmt.Errorf("listing devices: %w", err)
	}

	for _, dev := range candidates {
		ok, err := hasKey(dev.Path)
		if err != nil {
			continue // skip unreadable devices
		}
		if ok {
			return &dev, nil
		}
	}

	return nil, fmt.Errorf("no cryptclient USB device found")
}

// hasKey tells whether a device carries a key, as a file or in raw sectors.
func hasKey(path string) (bool, error) {
	if runtime.GOOS == "windows" {
		return fileHasKey(path)
	}
	if ok, err := hasRawMagic(path); err == nil && ok {
		return true, nil
	}
	if !isUSBDisk(path) {
		return false, nil // only a USB disk can be the stick: never look into the system disk's files
	}
	return fileHasKey(path)
}

// isUSBDisk tells whether a Linux block device sits on the USB bus (its sysfs path goes through it).
func isUSBDisk(path string) bool {
	if runtime.GOOS != "linux" {
		return runtime.GOOS == "darwin" // listDarwin; macOS is untested anyway
	}
	p, err := filepath.EvalSymlinks(filepath.Join("/sys/class/block", filepath.Base(path)))
	return err == nil && strings.Contains(p, "/usb")
}

// hasRawMagic checks if a device has the expected magic at MagicOffset (a raw key).
func hasRawMagic(path string) (bool, error) {
	if runtime.GOOS == "windows" {
		return false, nil
	}
	f, err := openRaw(path)
	if err != nil {
		return false, err
	}
	defer f.Close()

	buf := make([]byte, len(MagicBytes))
	_, err = f.ReadAt(buf, MagicOffset)
	if err != nil {
		return false, err
	}

	return string(buf) == string(MagicBytes), nil
}

// openRaw opens a block device for raw reading.
func openRaw(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY, 0)
}

// listCandidates returns candidate block device paths for the current OS.
func listCandidates() ([]Device, error) {
	switch runtime.GOOS {
	case "linux":
		return listLinux()
	case "darwin":
		return listDarwin()
	case "windows":
		return listWindowsUSB()
	default:
		return nil, fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}
}

// listLinux scans /dev/sd* and /dev/vd* block devices.
func listLinux() ([]Device, error) {
	entries, err := os.ReadDir("/dev")
	if err != nil {
		return nil, err
	}

	var devs []Device
	for _, e := range entries {
		name := e.Name()
		// Match sdX or vdX but not sdXN (partitions)
		if (strings.HasPrefix(name, "sd") || strings.HasPrefix(name, "vd")) &&
			len(name) == 3 {
			devs = append(devs, Device{Path: "/dev/" + name, Label: name})
		}
	}
	return devs, nil
}

// listDarwin scans /dev/rdisk* (raw disk devices on macOS).
func listDarwin() ([]Device, error) {
	entries, err := os.ReadDir("/dev")
	if err != nil {
		return nil, err
	}

	var devs []Device
	for _, e := range entries {
		name := e.Name()
		// rdisk0, rdisk1, etc. but not rdisk0s1 (partitions)
		if strings.HasPrefix(name, "rdisk") && !strings.Contains(name, "s") {
			devs = append(devs, Device{Path: "/dev/" + name, Label: name})
		}
	}
	return devs, nil
}
