package usb

import (
	"bytes"
	"cryptclient/nowindow"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

// The key lives in a small folder on the stick's own file system: .secdisk/key.bin (the encrypted key)
// and a serial binding per OS family (serial.bin on Windows, serial-linux.bin, serial-darwin.bin). The
// same stick works on Linux and Windows. On Windows a normal program may not open a physical drive at
// all (that needs administrator rights, and SSHFS-Win does not work with them); on Linux this needs no
// sudo, no udev access rule and no repartitioning. Sticks prepared on Linux before keep their key in raw
// sectors (rawkey.go) and still work there. A copy of the folder is useless: since key format v3 the key
// is sealed with a secret the server releases only after the full login.

// The name is from the product's earlier name (secdisk) and stays: sticks already set up keep their key
// there.
const keyDir = ".secdisk"

// fileRoot finds the root of the stick's file system ("E:\" or /media/user/CRYPTSTORE) from its device
// path. It is a variable so the file handling can be tested without a stick.
var fileRoot = stickRoot

func stickRoot(devicePath string) (string, error) {
	if runtime.GOOS == "windows" {
		return winRootFromPowerShell(devicePath)
	}
	if r := MountPath(devicePath); r != "" {
		return r, nil
	}
	return "", fmt.Errorf("the stick's file system is not mounted (open the stick in the file manager, or plug it in again)")
}

// usesFiles tells whether the key of the stick at devicePath is kept in the .secdisk folder rather than
// in raw sectors: always on Windows; elsewhere unless the stick carries a raw key from an older version.
func usesFiles(devicePath string) bool {
	if runtime.GOOS == "windows" {
		return true
	}
	ok, err := hasRawMagic(devicePath)
	return err != nil || !ok
}

func ps(script string) (string, error) {
	out, err := nowindow.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", script).Output()
	return strings.TrimSpace(string(out)), err
}

func winDiskNumber(devicePath string) (int, error) {
	p := strings.TrimPrefix(strings.TrimPrefix(devicePath, `\\.\`), `//./`)
	if !strings.HasPrefix(strings.ToLower(p), "physicaldrive") {
		return 0, fmt.Errorf("not a physical drive path: %s", devicePath)
	}
	return strconv.Atoi(p[len("physicaldrive"):])
}

func winRootFromPowerShell(devicePath string) (string, error) {
	n, err := winDiskNumber(devicePath)
	if err != nil {
		return "", err
	}
	out, err := ps(fmt.Sprintf(`(Get-Partition -DiskNumber %d -ErrorAction Stop | Where-Object { $_.DriveLetter } | Select-Object -First 1).DriveLetter`, n))
	if err != nil || len(out) != 1 {
		return "", fmt.Errorf("the stick has no drive letter (is it formatted and plugged in?)")
	}
	return strings.ToUpper(out) + `:\`, nil
}

// WindowsMountRoot is where the stick's files are (its drive letter), or "" when unknown.
func WindowsMountRoot(devicePath string) string {
	r, err := fileRoot(devicePath)
	if err != nil {
		return ""
	}
	return r
}

// listWindowsUSB lists the physical USB disks only, never the system disk.
func listWindowsUSB() ([]Device, error) {
	out, err := ps(`Get-Disk | Where-Object { $_.BusType -eq 'USB' } | ForEach-Object { "$($_.Number)|$($_.FriendlyName)" }`)
	if err != nil {
		return nil, fmt.Errorf("listing USB disks: %w", err)
	}
	var devs []Device
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		num, name, _ := strings.Cut(line, "|")
		if _, err := strconv.Atoi(num); err != nil {
			continue
		}
		devs = append(devs, Device{Path: `\\.\PhysicalDrive` + num, Label: strings.TrimSpace(name)})
	}
	return devs, nil
}

// ListRemovable lists the devices that may be the stick on this OS (Windows: USB disks only).
func ListRemovable() ([]Device, error) {
	if runtime.GOOS == "windows" {
		return listWindowsUSB()
	}
	return listCandidates()
}

func filePath(devicePath, name string) (string, error) {
	root, err := fileRoot(devicePath)
	if err != nil {
		return "", err
	}
	return filepath.Join(root, keyDir, name), nil
}

func fileRead(devicePath, name string) ([]byte, error) {
	p, err := filePath(devicePath, name)
	if err != nil {
		return nil, err
	}
	return os.ReadFile(p)
}

func fileWrite(devicePath, name string, data []byte) error {
	p, err := filePath(devicePath, name)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return fmt.Errorf("writing to the stick: %w", err)
	}
	if runtime.GOOS == "windows" {
		_ = nowindow.Command("attrib", "+h", filepath.Dir(p)).Run()
	}
	tmp := p + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("writing to the stick: %w", err)
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	_ = os.Remove(p)
	if err := os.Rename(tmp, p); err != nil {
		return err
	}
	return syncDir(filepath.Dir(p))
}

// syncDir writes the folder's entries (the rename above) and, on FAT, the allocation table to the stick.
// Without it the file's data was on the stick but its new name and size could still wait in the cache: a
// stick pulled out of a VirtualBox VM right after setup came back with an empty key.bin (2026-10-31).
// Windows cannot open a folder for this; its removable drives are written through by default.
func syncDir(dir string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("writing to the stick: %w", err)
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		return fmt.Errorf("writing to the stick: %w", err)
	}
	return nil
}

func fileHasKey(devicePath string) (bool, error) {
	b, err := fileRead(devicePath, "key.bin")
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return len(b) > 0, nil
}

func fileReadKey(devicePath string) ([]byte, error) {
	b, err := fileRead(devicePath, "key.bin")
	if err != nil {
		return nil, fmt.Errorf("reading the key from the stick: %w", err)
	}
	if len(b) == 0 || len(b) > KeySize {
		return nil, fmt.Errorf("invalid key length on the stick: %d", len(b))
	}
	return b, nil
}

func fileWriteKey(devicePath string, blob []byte) error {
	if len(blob) > KeySize {
		return fmt.Errorf("key blob too large: %d bytes (max %d)", len(blob), KeySize)
	}
	return fileWrite(devicePath, "key.bin", blob)
}

// bindingFile is this OS family's serial binding: each OS reads the serial number its own way, so
// the same stick can read differently on Linux and Windows.
func bindingFile(goos string) string {
	if goos == "windows" {
		return "serial.bin" // the name from before sticks moved between systems
	}
	return "serial-" + goos + ".bin"
}

var bindingOSes = []string{"windows", "linux", "darwin"}

func fileWriteBinding(devicePath string, hash []byte) error {
	return fileWrite(devicePath, bindingFile(runtime.GOOS), hash)
}

// fileStoredBinding returns this OS family's binding, or zeros when the stick has none at all. A stick
// bound only on another OS (prepared on Windows, now on Linux, or the other way) is bound here at its
// first use, to the serial number as this OS reads it: firstUse is then true.
func fileStoredBinding(devicePath string) (hash []byte, firstUse bool, err error) {
	b, err := fileRead(devicePath, bindingFile(runtime.GOOS))
	if err == nil || !errors.Is(err, os.ErrNotExist) {
		return b, false, err
	}
	for _, goos := range bindingOSes {
		if goos == runtime.GOOS {
			continue
		}
		if _, err := fileRead(devicePath, bindingFile(goos)); err == nil {
			return nil, true, nil
		}
	}
	return make([]byte, SerialHashLen), false, nil // not bound
}

func fileSameBinding(a, b []byte) bool { return bytes.Equal(a, b) }
