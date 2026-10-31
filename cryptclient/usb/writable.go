package usb

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"runtime"
)

// CheckWritable tells, before any question about passwords, whether this process may prepare the
// stick. A stick with a mounted file system gets the key as a file and needs nothing more. Otherwise
// it has to be erased and formatted first, which on Linux needs administrator rights.
func CheckWritable(devicePath string) error {
	if runtime.GOOS == "windows" || MountPath(devicePath) != "" {
		return nil // the key goes into a folder on the stick's mounted file system
	}
	if _, err := os.Stat(PartitionPath(devicePath)); err == nil && os.Geteuid() != 0 {
		return nil // a partition the client can mount itself (PrepareFiles); erasing is asked for later
	}
	f, err := os.OpenFile(devicePath, os.O_RDWR, 0)
	if errors.Is(err, fs.ErrPermission) {
		return fmt.Errorf("writing to %s needs administrator rights. Run the command with sudo, e.g.\n"+
			"    sudo cryptclient init-usb", devicePath)
	}
	if err != nil {
		return fmt.Errorf("opening %s: %w", devicePath, err)
	}
	return f.Close()
}
