package usb

import (
	"os"
	"path/filepath"
	"runtime"
	"time"
)

// WatchEject polls the device path and calls onEject when the device
// disappears (i.e. USB stick is physically removed).
//
// Runs in a goroutine. Call cancel() to stop watching.
// onEject is called once when device removal is detected.
func WatchEject(devicePath string, pollInterval time.Duration, onEject func()) {
	if runtime.GOOS == "windows" {
		// Finding the drive letter takes a PowerShell run; it is done once. Then the stick's key
		// folder on that drive is checked, which costs nothing (the tray stays connected for hours).
		root := WindowsMountRoot(devicePath)
		for {
			time.Sleep(pollInterval)
			if root == "" {
				onEject()
				return
			}
			if _, err := os.Stat(filepath.Join(root, keyDir)); err != nil {
				onEject()
				return
			}
		}
	}
	for {
		time.Sleep(pollInterval)

		// The device node goes away with the stick. Only its existence is checked: a user who reads the
		// key from the .secdisk folder may not be allowed to open the device itself.
		if _, err := os.Stat(devicePath); err != nil {
			onEject()
			return
		}
	}
}
