package volume

import (
	"os"
	"runtime"
	"testing"
)

// plainDir is where the decrypted volume is shown: a free drive letter on Windows (the SSH drive
// takes one of S-Z), a temporary directory elsewhere.
func plainDir(t *testing.T) string {
	t.Helper()
	if runtime.GOOS != "windows" {
		return t.TempDir()
	}
	for l := 'Q'; l >= 'J'; l-- {
		d := string(l) + ":"
		if _, err := os.Stat(d + `\`); err != nil {
			return d
		}
	}
	t.Skip("no free drive letter")
	return ""
}
