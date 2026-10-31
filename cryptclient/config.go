package main

import (
	"os"
	"path/filepath"
	"strings"

	"cryptclient/appdir"
)

// The client remembers the username on this computer, so that connecting asks only for the password.
// It is kept here and not on the stick: a lost stick should not tell its finder whose it is.

func usernameFile() string {
	dir, err := os.UserConfigDir()
	if err != nil {
		return ""
	}
	return filepath.Join(appdir.In(dir), "username")
}

func savedUsername() string {
	f := usernameFile()
	if f == "" {
		return ""
	}
	b, err := os.ReadFile(f)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// rememberUsername stores the username after a successful connect. Failing to store it only means
// it is asked again next time.
func rememberUsername(username string) {
	f := usernameFile()
	if f == "" || username == "" || username == savedUsername() {
		return
	}
	if err := os.MkdirAll(filepath.Dir(f), 0o700); err != nil {
		return
	}
	os.WriteFile(f, []byte(username+"\n"), 0o600) //nolint
}
