package diskenc

import (
	"cryptclient/nowindow"
	"path/filepath"
	"strings"
)

// Advice names the encryption to turn on.
func Advice() string {
	return "BitLocker (Settings, Privacy & security, Device encryption; or Control Panel, BitLocker Drive Encryption)"
}

// check asks Explorer's BitLocker property of the drive, which works without administrator rights
// (manage-bde needs them). The values are those Explorer uses for its padlock icon.
func check(path string) Result {
	drive := filepath.VolumeName(path)
	if len(drive) != 2 || drive[1] != ':' {
		return Result{Unknown, "not on a drive letter"}
	}
	ps := `(New-Object -ComObject Shell.Application).NameSpace('` + drive + `\').Self.ExtendedProperty('System.Volume.BitLockerProtection')`
	out, err := nowindow.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", ps).Output()
	if err != nil {
		return Result{Unknown, "could not ask Windows about BitLocker"}
	}
	return bitlocker(drive, strings.TrimSpace(string(out)))
}
