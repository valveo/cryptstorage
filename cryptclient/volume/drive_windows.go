package volume

import (
	"errors"

	"golang.org/x/sys/windows"
)

// freeDrive returns a drive letter nothing uses, below the ones the storage itself takes (S and up).
// GetLogicalDrives also counts letters without a medium (an empty card reader), which a look at the
// root would take for free.
func freeDrive() (string, error) {
	used, err := windows.GetLogicalDrives()
	if err != nil {
		return "", err
	}
	for l := 'R'; l >= 'G'; l-- {
		if used&(1<<uint(l-'A')) == 0 {
			return string(l) + ":", nil
		}
	}
	return "", errors.New("no free drive letter for checking the volume")
}
