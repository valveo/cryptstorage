package main

import (
	"bufio"
	"os"
	"os/user"
	"path/filepath"
	"strings"

	"cryptclient/appdir"
)

// The settings file ~/.config/cryptstorage/env holds lines like CRYPTSTORAGE_SERVER=https://... It is read
// by the udev rule's user service and by the client itself, so the settings also survive sudo (which
// drops the environment): under sudo the file of the user who ran sudo is read. A variable already in
// the environment wins. Only the client's own variables are taken, so that the file cannot change
// what the programs started by the client (sshfs, gocryptfs) run as root.

func envFilePath() string {
	if os.Geteuid() == 0 {
		if name := os.Getenv("SUDO_USER"); name != "" {
			if u, err := user.Lookup(name); err == nil {
				return filepath.Join(appdir.In(filepath.Join(u.HomeDir, ".config")), "env")
			}
		}
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		return ""
	}
	return filepath.Join(appdir.In(dir), "env")
}

// startEnv holds the client's variables that the real environment set when the program started; they
// win over the file, also when the file is read again.
var startEnv map[string]bool

func ownSetting(key string) bool {
	return strings.HasPrefix(key, "CRYPTSTORAGE_") || strings.HasPrefix(key, "CRYPTCLIENT_")
}

// reloadEnvFile reads the settings file again, so that a program that keeps running (the tray) follows
// a change made meanwhile, e.g. `cryptclient server` in a terminal.
func reloadEnvFile(path string) {
	if startEnv == nil {
		loadEnvFile(path)
		return
	}
	for _, kv := range os.Environ() {
		key, _, _ := strings.Cut(kv, "=")
		if ownSetting(key) && !startEnv[key] {
			os.Unsetenv(key)
		}
	}
	loadEnvFile(path)
}

func loadEnvFile(path string) {
	if startEnv == nil {
		startEnv = map[string]bool{}
		for _, kv := range os.Environ() {
			if key, _, _ := strings.Cut(kv, "="); ownSetting(key) {
				startEnv[key] = true
			}
		}
	}
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		key, value, ok := strings.Cut(line, "=")
		if !ok || strings.HasPrefix(line, "#") {
			continue
		}
		key = strings.TrimSpace(key)
		if !ownSetting(key) {
			continue
		}
		if _, set := os.LookupEnv(key); set {
			continue
		}
		value = strings.TrimSpace(value)
		if len(value) >= 2 && (value[0] == '"' || value[0] == '\'') && value[len(value)-1] == value[0] {
			value = value[1 : len(value)-1]
		}
		os.Setenv(key, value)
	}
}
