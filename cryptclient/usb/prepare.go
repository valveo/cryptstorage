package usb

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"time"
)

// ErrNoFileSystem means the stick has no file system this computer can mount, so the key folder has
// nowhere to go: the stick has to be formatted (on Linux, init-usb offers to erase it).
var ErrNoFileSystem = errors.New("the stick has no file system that can be opened")

// PrepareFiles readies a stick for a key in its .secdisk folder (Linux, macOS): it mounts the stick's
// file system if the desktop has not, and clears a raw key that an older version left 1 MiB into the
// stick, so that only the new key is ever read and no old copy of a key stays behind.
func PrepareFiles(devicePath string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	if MountPath(devicePath) == "" && runtime.GOOS == "linux" {
		part := PartitionPath(devicePath)
		if _, err := os.Stat(part); err != nil {
			return ErrNoFileSystem
		}
		// as the desktop does when the stick is opened in the file manager; no administrator rights
		if out, err := exec.Command("udisksctl", "mount", "--no-user-interaction", "-b", part).CombinedOutput(); err != nil {
			return fmt.Errorf("%w (udisksctl: %v %s)", ErrNoFileSystem, err, out)
		}
		for i := 0; i < 20 && MountPath(devicePath) == ""; i++ {
			time.Sleep(100 * time.Millisecond)
		}
	}
	if MountPath(devicePath) == "" {
		return ErrNoFileSystem
	}
	raw, err := hasRawMagic(devicePath)
	if err != nil || !raw {
		return nil
	}
	if err := clearRawKey(devicePath); err != nil {
		return fmt.Errorf("this stick still holds a key from an older version in its raw sectors, and clearing it "+
			"failed (%v). Plug the stick in again, or run the command once with sudo", err)
	}
	return nil
}

// clearRawKey zeroes the raw key area (magic, key, serial binding): sectors this program wrote itself,
// in the gap before the first partition (init-usb checked that gap before writing).
func clearRawKey(devicePath string) error {
	f, err := os.OpenFile(devicePath, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.WriteAt(make([]byte, rawAreaEnd-MagicOffset), MagicOffset); err != nil {
		return err
	}
	return f.Sync()
}
