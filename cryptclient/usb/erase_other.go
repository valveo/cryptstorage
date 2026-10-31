//go:build !linux

package usb

import (
	"fmt"
	"runtime"
)

// EraseStick is done on Linux only. On Windows the key is a file on the stick, so nothing is in
// the way; on macOS the stick has to be repartitioned by hand.
func EraseStick(devicePath string) error {
	return fmt.Errorf("erasing the stick is not supported on %s; repartition it by hand", runtime.GOOS)
}
