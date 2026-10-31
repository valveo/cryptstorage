package usb

import (
	"cryptclient/nowindow"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// SerialOffset is the sector where the stick's serial number HMAC is stored.
// Located right after the magic bytes + key.
const SerialOffset = int64(2054) * 512
const SerialHashLen = 32 // SHA256 = 32 bytes

// bindingKey is an internal HMAC key for binding the serial number.
const bindingKey = "cryptclient-serial-bind-v1"

// GetSerial returns the USB device's serial number.
// Returns an error if the serial number is not found.
func GetSerial(devicePath string) (string, error) {
	switch runtime.GOOS {
	case "linux":
		return getSerialLinux(devicePath)
	case "darwin":
		return getSerialDarwin(devicePath)
	case "windows":
		return getSerialWindows(devicePath)
	default:
		return "", fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}
}

// getSerialLinux reads the serial number from /sys/block/<dev>/device/serial.
func getSerialLinux(devicePath string) (string, error) {
	devName := filepath.Base(devicePath) // e.g. "sdb"

	// Try the direct path first
	paths := []string{
		fmt.Sprintf("/sys/block/%s/device/serial", devName),
		fmt.Sprintf("/sys/block/%s/../serial", devName),
	}
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err == nil {
			s := strings.TrimSpace(string(data))
			if s != "" {
				return s, nil
			}
		}
	}

	// Fallback: udevadm info
	out, err := exec.Command("udevadm", "info", "--query=property", "--name="+devicePath).Output()
	if err != nil {
		return "", fmt.Errorf("serial not found for %s", devicePath)
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, "ID_SERIAL_SHORT=") {
			return strings.TrimPrefix(line, "ID_SERIAL_SHORT="), nil
		}
		if strings.HasPrefix(line, "ID_SERIAL=") {
			return strings.TrimPrefix(line, "ID_SERIAL="), nil
		}
	}
	return "", fmt.Errorf("serial not found in udevadm output for %s", devicePath)
}

// getSerialDarwin lukee USB-laitteen sarjanumeron macOS:lla.
//
// Strategy:
//  1. system_profiler SPUSBDataType – gives the physical USB device's serial number
//     (immutable, independent of partitioning or formatting)
//  2. diskutil info – fallback if system_profiler does not find the device
//
// system_profiler is more reliable than diskutil because it reads the serial number
// directly from the USB device descriptor, not from the filesystem.
func getSerialDarwin(devicePath string) (string, error) {
	// Convert /dev/disk2 → disk2 → find the matching BSD device in system_profiler
	diskName := filepath.Base(devicePath) // e.g. "disk2"

	serial, err := getSerialDarwinSystemProfiler(diskName)
	if err == nil && serial != "" {
		return serial, nil
	}

	// Fallback: diskutil info gives Volume UUID or Media UUID
	// These are persistent per partition/media and work for identification
	return getSerialDarwinDiskutil(devicePath)
}

// getSerialDarwinSystemProfiler fetches the serial number with the system_profiler command.
// This gives the physical USB device's serial number.
func getSerialDarwinSystemProfiler(diskName string) (string, error) {
	out, err := exec.Command("system_profiler", "SPUSBDataType", "-xml").Output()
	if err != nil {
		return "", fmt.Errorf("system_profiler failed: %w", err)
	}

	// Parse the XML by looking for bsd_name + serial_num pairs
	// Structure: ...  <key>bsd_name</key><string>disk2</string>
	//               <key>serial_num</key><string>1234567890</string>
	lines := strings.Split(string(out), "\n")
	for i, line := range lines {
		if strings.Contains(line, "<string>"+diskName+"</string>") {
			// Look for serial_num near this spot (±20 lines)
			start := max(0, i-20)
			end := min(len(lines), i+20)
			for _, nearby := range lines[start:end] {
				nearby = strings.TrimSpace(nearby)
				if strings.HasPrefix(nearby, "<key>serial_num</key>") {
					// The next line is the value
					continue
				}
				// Look for the value line after the serial_num key
			}
			_ = start
			_ = end

			// Simpler approach: look for serial_num in the whole block
			block := strings.Join(lines[start:end], "\n")
			if idx := strings.Index(block, "<key>serial_num</key>"); idx >= 0 {
				rest := block[idx+len("<key>serial_num</key>"):]
				rest = strings.TrimSpace(rest)
				if strings.HasPrefix(rest, "<string>") {
					rest = strings.TrimPrefix(rest, "<string>")
					if end := strings.Index(rest, "</string>"); end >= 0 {
						serial := rest[:end]
						if serial != "" {
							return serial, nil
						}
					}
				}
			}
		}
	}
	return "", fmt.Errorf("disk %s not found in system_profiler output", diskName)
}

// getSerialDarwinDiskutil fetches the serial number with the diskutil info command.
// Returns the Media UUID, which is persistent per physical medium.
func getSerialDarwinDiskutil(devicePath string) (string, error) {
	out, err := exec.Command("diskutil", "info", devicePath).Output()
	if err != nil {
		return "", fmt.Errorf("diskutil info failed: %w", err)
	}

	// Priority order:
	// 1. "Disk / Partition UUID" (persistent per physical disk)
	// 2. "Media UUID"
	// 3. "Volume UUID" (may change if the disk is reformatted)
	priorities := []string{
		"Disk / Partition UUID:",
		"Media UUID:",
		"Volume UUID:",
	}

	values := make(map[string]string)
	for _, line := range strings.Split(string(out), "\n") {
		for _, key := range priorities {
			if strings.Contains(line, key) {
				parts := strings.SplitN(line, ":", 2)
				if len(parts) == 2 {
					val := strings.TrimSpace(parts[1])
					if val != "" {
						values[key] = val
					}
				}
			}
		}
	}

	for _, key := range priorities {
		if val, ok := values[key]; ok {
			return val, nil
		}
	}

	return "", fmt.Errorf("no UUID found in diskutil output for %s", devicePath)
}

// getSerialWindows reads the serial number through WMI.
// Uses Win32_DiskDrive, which gives the physical serial number,
// not the filesystem's volume serial number.
func getSerialWindows(devicePath string) (string, error) {
	// devicePath may be e.g. "\\.\PhysicalDrive1" or "D:"
	var ps string

	if strings.HasPrefix(devicePath, `\\.\PhysicalDrive`) ||
		strings.HasPrefix(devicePath, `//./PhysicalDrive`) {
		// Physical disk – fetch SerialNumber directly
		driveIndex := strings.TrimPrefix(devicePath, `\\.\PhysicalDrive`)
		driveIndex = strings.TrimPrefix(driveIndex, `//./PhysicalDrive`)
		ps = fmt.Sprintf(
			`(Get-WmiObject Win32_DiskDrive | Where-Object { $_.Index -eq %s }).SerialNumber`,
			driveIndex,
		)
	} else {
		// Drive letter (e.g. "D:") – find the physical disk first
		driveLetter := strings.TrimSuffix(
			strings.TrimPrefix(strings.TrimPrefix(devicePath, `\\.\`), `//./`), ":")
		ps = fmt.Sprintf(`
$drive = Get-WmiObject Win32_LogicalDiskToPartition | Where-Object {
    $_.Dependent -like "*%s:*"
} | Select-Object -First 1
$disk = ($drive.Antecedent -replace '.*Disk #(\d+).*','$1')
(Get-WmiObject Win32_DiskDrive | Where-Object { $_.Index -eq $disk }).SerialNumber
`, driveLetter)
	}

	cmd := nowindow.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", ps)
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("WMI query failed: %w", err)
	}

	serial := strings.TrimSpace(string(out))
	if serial == "" {
		return "", fmt.Errorf("empty serial from WMI for %s", devicePath)
	}
	return serial, nil
}

// --- Binding ---

// ComputeSerialHash computes an HMAC-SHA256 of the serial number.
func ComputeSerialHash(serial string) []byte {
	mac := hmac.New(sha256.New, []byte(bindingKey))
	mac.Write([]byte(serial))
	return mac.Sum(nil)
}

// WriteSerialBinding writes the serial number HMAC to the stick's raw sector.
func WriteSerialBinding(devicePath string, serial string) error {
	hash := ComputeSerialHash(serial)
	if usesFiles(devicePath) {
		return fileWriteBinding(devicePath, hash)
	}
	f, err := os.OpenFile(devicePath, os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("opening device: %w", err)
	}
	defer f.Close()
	if _, err := f.WriteAt(hash, SerialOffset); err != nil {
		return fmt.Errorf("writing serial hash: %w", err)
	}
	return f.Sync()
}

// VerifySerialBinding checks that the stick's serial number matches the stored hash.
func VerifySerialBinding(devicePath string) error {
	storedHash := make([]byte, SerialHashLen)
	if usesFiles(devicePath) {
		h, firstUse, err := fileStoredBinding(devicePath)
		if firstUse {
			return bindHere(devicePath)
		}
		if err != nil || len(h) != SerialHashLen {
			return fmt.Errorf("reading the serial binding from the stick failed")
		}
		storedHash = h
	} else {
		f, err := os.OpenFile(devicePath, os.O_RDONLY, 0)
		if err != nil {
			return fmt.Errorf("opening device: %w", err)
		}
		defer f.Close()
		if _, err := f.ReadAt(storedHash, SerialOffset); err != nil {
			return fmt.Errorf("reading serial hash: %w", err)
		}
	}

	// All zeros → not bound
	allZero := true
	for _, b := range storedHash {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		fmt.Println("⚠️  Warning: this USB stick has no serial binding.")
		return nil
	}

	serial, err := GetSerial(devicePath)
	if err != nil {
		fmt.Printf("⚠️  Warning: could not verify serial number: %v\n", err)
		return nil
	}

	expected := ComputeSerialHash(serial)
	if !hmac.Equal(storedHash, expected) {
		return fmt.Errorf(
			"SERIAL MISMATCH: this key was created on a different USB stick.\n"+
				"  Stored:   %s\n"+
				"  Current:  %s\n"+
				"  This may indicate the key file was copied to another device.",
			hex.EncodeToString(storedHash),
			hex.EncodeToString(expected),
		)
	}
	return nil
}

// bindHere binds a stick prepared on another OS family to its serial number as this one reads it.
func bindHere(devicePath string) error {
	serial, err := GetSerial(devicePath)
	if err != nil {
		fmt.Printf("⚠️  Warning: could not read the serial number to bind the stick here: %v\n", err)
		return nil
	}
	if err := fileWriteBinding(devicePath, ComputeSerialHash(serial)); err != nil {
		fmt.Printf("⚠️  Warning: could not bind the stick to its serial number here: %v\n", err)
		return nil
	}
	fmt.Printf("✓ First use of this stick on %s: bound to its serial number as read here (%s).\n", runtime.GOOS, serial)
	return nil
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
