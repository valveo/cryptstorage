// Package appdir names the client's own folders. The product was called secdisk before it became
// CryptStorage; folders an older version made under the old name are moved to the new one the
// first time they are needed, so that settings, the saved username and the downloaded programs stay.
package appdir

import (
	"os"
	"path/filepath"
)

const (
	// Name is the folder name under the user's configuration, cache and data folders.
	Name = "cryptstorage"
	// Legacy is the name older versions used.
	Legacy = "secdisk"
)

// In returns base\cryptstorage. When only base\secdisk exists (an older version's), it is renamed
// first; if that fails (a file in it is open, e.g. the old tray's log) the old folder is used as it
// is, so nothing is lost.
func In(base string) string {
	dir := filepath.Join(base, Name)
	old := filepath.Join(base, Legacy)
	if _, err := os.Lstat(dir); err == nil {
		return dir
	}
	fi, err := os.Lstat(old)
	if err != nil || !fi.IsDir() {
		return dir
	}
	if os.Rename(old, dir) == nil {
		return dir
	}
	return old
}
