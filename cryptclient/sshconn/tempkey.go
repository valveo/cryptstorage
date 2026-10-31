package sshconn

import (
	"fmt"
	"os"
	"runtime"
)

// writeTempKey writes PEM bytes to a secure temp file.
// Returns the file path. Caller must call secureDelete() after use.
func writeTempKey(pemBytes []byte) (string, error) {
	f, err := os.CreateTemp("", "cryptkey-*.pem")
	if err != nil {
		return "", fmt.Errorf("creating temp key file: %w", err)
	}
	defer f.Close()

	// Restrict permissions immediately
	if runtime.GOOS != "windows" {
		if err := f.Chmod(0600); err != nil {
			os.Remove(f.Name())
			return "", fmt.Errorf("setting key file permissions: %w", err)
		}
	}

	if _, err := f.Write(pemBytes); err != nil {
		os.Remove(f.Name())
		return "", fmt.Errorf("writing key file: %w", err)
	}

	return f.Name(), nil
}

// secureDelete overwrites the file with zeros before removing it.
// Best-effort: logs nothing on failure, removal still attempted.
func secureDelete(path string) {
	f, err := os.OpenFile(path, os.O_WRONLY, 0600)
	if err == nil {
		info, _ := f.Stat()
		if info != nil {
			zeros := make([]byte, info.Size())
			f.WriteAt(zeros, 0) //nolint
			f.Sync()            //nolint
		}
		f.Close()
	}
	os.Remove(path)
}
