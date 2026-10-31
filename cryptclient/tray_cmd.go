package main

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"time"

	"golang.org/x/term"

	"cryptclient/tray"
	"cryptclient/usb"
)

const passwordTries = 3

// desktopUI is where the connect flow asks its questions when it runs without a terminal: zenity
// dialogs on Linux (tray.Dialogs), the client's own windows on Windows (tray_windows.go), with
// notifications.
type desktopUI interface {
	asker
	Secret(label string) (string, error)
	Error(msg string)
	Notify(body string)
}

// cmdTray is the padlock icon that stays running: next to the clock on Windows (CryptStorage.exe), in the
// panel on Linux (tray_app.go). On Linux, with --auto-connect it was started by the udev rule (the
// cryptstorage-tray@ user service) for one inserted stick: it leaves the stick to a running tray, and
// otherwise connects once with desktop dialogs. Without a desktop it falls back to the terminal.
func cmdTray() {
	if runtime.GOOS == "windows" {
		cmdTrayWindows()
		return
	}
	auto := len(os.Args) > 2 && os.Args[2] == "--auto-connect"
	if auto && trayRunning() {
		fmt.Fprintln(os.Stderr, "The CryptStorage tray is running and opens the stick.")
		return
	}
	if !auto && cmdTrayDesktop() {
		return
	}
	d, ok := tray.NewDialogs()
	if !ok {
		if term.IsTerminal(int(os.Stdin.Fd())) {
			cmdConnect()
			return
		}
		// started by the udev rule outside a desktop session (or without zenity): nobody to ask
		fmt.Fprintln(os.Stderr, "No desktop session or zenity found; connect with `cryptclient connect` in a terminal.")
		os.Exit(1)
	}
	if err := trayConnect(d, auto); err != nil {
		if !errors.Is(err, tray.ErrCancelled) {
			fmt.Fprintln(os.Stderr, err)
			d.Error(err.Error())
		}
		os.Exit(1)
	}
}

func trayConnect(d desktopUI, auto bool) error {
	if !serverConfigured() {
		return errNoServer
	}
	devicePath, err := findStick()
	if err != nil {
		return err
	}
	if auto {
		// The user service is started for every user logged in, and for every USB stick with a file
		// system (the rule cannot look into files). Only a CryptStorage stick this user can read gets a
		// dialog: a raw key the seat's user may read (the rule gives the access), or the key folder on
		// a file system the desktop mounted for this user. The others stop here without a word.
		disk, ok := usb.AutoDevice(devicePath, 20*time.Second)
		if !ok {
			fmt.Fprintf(os.Stderr, "%s is not a CryptStorage stick this user can open; not asking.\n", devicePath)
			os.Exit(0)
		}
		devicePath = disk
	}
	st, err := trayOpen(d, devicePath)
	if err != nil {
		return err
	}
	trayConnected(d, st)
	stayConnected(st.device, nil, func(removed bool) {})
	d.Notify("Storage disconnected.")
	return nil
}

// trayOpen asks for the password (and on the way the username, a verification code, ...) with d and
// opens the storage of the stick at devicePath.
func trayOpen(d desktopUI, devicePath string) (*stick, error) {
	if err := checkStickServerEarly(devicePath); err != nil {
		return nil, err
	}
	var st *stick
	for try := 1; st == nil; try++ {
		password, err := d.Secret("Password for your CryptStorage stick:")
		if err != nil {
			return nil, err
		}
		if password == "" { // asked again here, not after the username
			if try == passwordTries {
				return nil, errors.New("no password was typed")
			}
			d.Error("The password is empty. Type it again.")
			continue
		}
		st, err = openStick(devicePath, password)
		if errors.Is(err, errWrongPassword) && try < passwordTries {
			d.Error("Wrong password. Try again.")
			continue
		}
		if err != nil {
			return nil, err
		}
	}
	defer st.wipe()

	username := savedUsername()
	if username == "" {
		var err error
		if username, err = d.Line("Username:"); err != nil {
			return nil, err
		}
	}
	if err := openE2EE(d, st, username); err != nil {
		return nil, err
	}
	rememberUsername(username)
	return st, nil
}

// trayConnected tells the user where the storage is and starts syncing when it is turned on.
func trayConnected(d desktopUI, st *stick) {
	d.Notify(fmt.Sprintf("Your storage is open at %s. Remove the stick to disconnect.", openVolume.plain))
	if st.oldFormat {
		d.Notify("The key on your stick uses an older, weaker protection. Run `cryptclient upgrade-key` to upgrade it.")
	}
	maybeStartSync(d, d.Notify)
}
