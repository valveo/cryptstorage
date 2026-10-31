package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"cryptclient/stickserver"
)

// The server address is asked once and saved in the settings file (envfile.go), so that setup, connect and
// the Start-menu shortcut work without CRYPTSTORAGE_SERVER in the environment. The environment still wins.

var errNoServer = errors.New("no server address is set: run `cryptclient setup`, or set CRYPTSTORAGE_SERVER")

func serverConfigured() bool {
	return os.Getenv("CRYPTSTORAGE_SERVER") != ""
}

// normalizeServer turns what the user typed into an API address: https:// is added when no scheme is
// given, a trailing slash is dropped. Plain http:// is kept as typed (a test server on the local network).
func normalizeServer(s string) string {
	s = strings.TrimRight(strings.TrimSpace(s), "/")
	if s == "" {
		return ""
	}
	if !strings.Contains(s, "://") {
		s = "https://" + s
	}
	return s
}

// askServer asks for the address until the server answers, then saves it. An empty answer stops.
// reachable checks the address the environment now holds.
func askServer(ask func(string) string, reachable func() error) error {
	if serverConfigured() {
		return nil
	}
	fmt.Println("Which server is your storage on? Your administrator gives you the address.")
	return askServerWith(ask, func(msg string) { fmt.Println(msg) }, reachable,
		"Server address (for example https://storage.example.com): ")
}

// askServerWith is askServer for any way of asking (the Windows tray asks in a window). say tells
// why an address did not work.
func askServerWith(ask func(string) string, say func(string), reachable func() error, label string) error {
	if serverConfigured() {
		return nil
	}
	for {
		s := normalizeServer(ask(label))
		if s == "" {
			return errNoServer
		}
		os.Setenv("CRYPTSTORAGE_SERVER", s)
		err := reachable()
		if err != nil && !strings.Contains(strings.SplitN(s, "://", 2)[1], "/") {
			// A server installed with the Ansible playbook serves the API under /api on the web UI's address
			os.Setenv("CRYPTSTORAGE_SERVER", s+"/api")
			if reachable() == nil {
				s, err = s+"/api", nil
			} else {
				os.Setenv("CRYPTSTORAGE_SERVER", s)
			}
		}
		if err != nil {
			say(fmt.Sprintf("The server at %s did not answer: %v\nCheck the address and try again, or leave it empty to stop.", s, err))
			os.Unsetenv("CRYPTSTORAGE_SERVER")
			continue
		}
		if path, err := saveSetting(envFilePath(), "CRYPTSTORAGE_SERVER", s); err != nil {
			fmt.Printf("The address could not be saved (%v); it will be asked again next time.\n", err)
		} else {
			fmt.Printf("✓ Server address saved to %s\n", path)
		}
		return nil
	}
}

// saveSetting sets key=value in the settings file, replacing an earlier line for the key and keeping the rest.
func saveSetting(path, key, value string) (string, error) {
	if path == "" {
		return "", errors.New("no settings folder on this computer")
	}
	var lines []string
	if b, err := os.ReadFile(path); err == nil && strings.TrimSpace(string(b)) != "" {
		for _, l := range strings.Split(strings.TrimRight(string(b), "\n"), "\n") {
			k, _, ok := strings.Cut(l, "=")
			if ok && strings.TrimSpace(k) == key {
				continue
			}
			lines = append(lines, l)
		}
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	lines = append(lines, key+"="+value)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", err
	}
	return path, os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600)
}

// serverChangeNote is what moving to another server means for the account and the stick.
const serverChangeNote = "Your account and your USB stick belong to one server. On the new server, create an account " +
	"with `cryptclient setup` (or Set up CryptStorage... in the tray menu): it prepares the stick again, and the key " +
	"for the old server on that stick is lost. Use another stick if you still need the old account."

// changeServer asks for a new server address and saves it. When nothing new is given, or it does not
// answer, the old address stays. The saved username belonged to the old server and is forgotten.
func changeServer(ask func(string) string, say func(string), reachable func() error, label string) error {
	old := os.Getenv("CRYPTSTORAGE_SERVER")
	os.Unsetenv("CRYPTSTORAGE_SERVER")
	if err := askServerWith(ask, say, reachable, label); err != nil {
		if old != "" {
			os.Setenv("CRYPTSTORAGE_SERVER", old)
		}
		return err
	}
	if os.Getenv("CRYPTSTORAGE_SERVER") != old {
		if f := usernameFile(); f != "" {
			os.Remove(f) //nolint
		}
	}
	return nil
}

// cmdServer shows the server address, or changes it: cryptclient server [address]
func cmdServer() {
	refuseElevated()
	if len(os.Args) < 3 {
		if s := os.Getenv("CRYPTSTORAGE_SERVER"); s != "" {
			fmt.Println(s)
		} else {
			fmt.Println("No server address is set.")
		}
		if dev, err := findStick(); err == nil {
			if rec, _ := stickserver.Load(getUSBMountPath(dev)); rec != nil && !stickserver.SameURL(rec.URL, os.Getenv("CRYPTSTORAGE_SERVER")) {
				fmt.Printf("The stick plugged in belongs to %s: cryptclient server %s\n", rec.URL, rec.URL)
			}
		}
		fmt.Printf("Change it with: cryptclient server <address>  (saved in %s)\n", envFilePath())
		return
	}
	typed := os.Args[2]
	asked := false
	ask := func(string) string {
		if asked {
			return ""
		}
		asked = true
		return typed
	}
	if err := changeServer(ask, func(msg string) { fmt.Println(msg) }, probeServer, ""); err != nil {
		fatal("the address was not changed: %v", err)
	}
	fmt.Println(serverChangeNote)
}
