package wingui

import (
	"errors"
	"os"
	"strings"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const (
	runKey   = `Software\Microsoft\Windows\CurrentVersion\Run`
	runValue = "CryptStorage"
	// oldRunValue started secdisk.exe, the tray's name before CryptStorage
	oldRunValue = "secdisk"
)

// Autostart reports whether this program starts when the user signs in. An older version's entry is
// replaced by one for this program, so that the setting stays as the user left it.
func Autostart() bool {
	k, err := registry.OpenKey(registry.CURRENT_USER, runKey, registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		return false
	}
	defer k.Close()
	if v, _, err := k.GetStringValue(runValue); err == nil && v != "" {
		return true
	}
	if v, _, err := k.GetStringValue(oldRunValue); err != nil || v == "" {
		return false
	}
	if SetAutostart(true) != nil {
		return true // the old entry still starts something; it is moved next time
	}
	k.DeleteValue(oldRunValue) //nolint
	return true
}

// SetAutostart turns starting at sign-in on (this program, as it is now installed) or off. It is the
// user's own setting (HKEY_CURRENT_USER), so it needs no administrator rights.
func SetAutostart(on bool) error {
	k, _, err := registry.CreateKey(registry.CURRENT_USER, runKey, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	if !on {
		for _, v := range []string{runValue, oldRunValue} {
			if err := k.DeleteValue(v); err != nil && !errors.Is(err, registry.ErrNotExist) {
				return err
			}
		}
		return nil
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	return k.SetStringValue(runValue, `"`+strings.ReplaceAll(exe, `"`, ``)+`"`)
}

// SingleInstance reports whether this is the only copy of the tray running for this user. The lock
// is held until the program ends.
func SingleInstance(name string) bool {
	_, err := windows.CreateMutex(nil, false, utf16(`Local\`+name))
	return !errors.Is(err, windows.ERROR_ALREADY_EXISTS)
}
