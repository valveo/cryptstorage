package sshconn

import "golang.org/x/sys/windows"

// volumeLabel returns the label of the volume mounted at root (e.g. `S:\`), or ok=false if it cannot be read.
func volumeLabel(root string) (label string, ok bool) {
	p, err := windows.UTF16PtrFromString(root)
	if err != nil {
		return "", false
	}
	buf := make([]uint16, windows.MAX_PATH+1)
	if err := windows.GetVolumeInformation(p, &buf[0], uint32(len(buf)), nil, nil, nil, nil, 0); err != nil {
		return "", false
	}
	return windows.UTF16ToString(buf), true
}
