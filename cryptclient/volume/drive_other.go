//go:build !windows

package volume

import "errors"

// freeDrive is only used on Windows; elsewhere the volume is checked in a temporary directory.
func freeDrive() (string, error) { return "", errors.New("no drive letters on this system") }
