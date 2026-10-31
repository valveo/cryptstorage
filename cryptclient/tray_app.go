//go:build windows || linux

package main

import (
	"errors"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"cryptclient/tray"
	"cryptclient/usb"
	"cryptclient/wingui"
)

// The tray icon that stays running: a padlock next to the clock on Windows (tray_windows.go), in the
// panel's tray area on Linux (tray_linux.go). Plugging in the stick asks for the password; the menu
// connects, disconnects and opens the folder. This file is what both share; the platform files draw
// the icon, show the dialogs and notifications, and tell when a stick may have been plugged in.

const appTitle = "CryptStorage"

// trayShell is the platform's part of the tray.
type trayShell interface {
	dialogs() trayDialogs
	// show changes the icon and its tooltip. Called with trayApp.mu held: must not call back.
	show(s wingui.IconState, tip string)
	notify(body string, warning bool)
	// menuChanged tells the desktop to read the menu again (Linux; Windows builds it on each click).
	menuChanged()
	quit()
	openFolder(path string) error
	autostart() bool
	setAutostart(on bool) error
	startSetup() error
	// iconPlace says where the user finds the icon, for the messages.
	iconPlace() string
}

// trayDialogs asks: windows of the client's own on Windows, zenity on Linux.
type trayDialogs interface {
	asker
	Secret(label string) (string, error)
	Error(msg string)
}

// appUI is the desktopUI of the connect flow: the platform's dialogs, and notifications that are
// also logged.
type appUI struct {
	trayDialogs
	a *trayApp
}

func (u appUI) Notify(body string) { u.a.notify(body) }

// menuItem is one line of the tray menu. An item with an empty Text is a separator.
type menuItem struct {
	ID       int
	Text     string
	Toggle   bool // a check box, ticked when Checked
	Checked  bool
	Disabled bool
}

const (
	menuStatus = iota + 1
	menuConnect
	menuDisconnect
	menuOpen
	menuOpenSync
	menuWebLogin
	menuAutostart
	menuSetup
	menuServer
	menuVersion
	menuExit
	menuServerLine
)

type trayApp struct {
	shell    trayShell
	mu       sync.Mutex
	state    wingui.IconState
	plain    string        // where the open storage is
	stop     chan struct{} // closed to disconnect; nil when there is nothing to stop
	done     chan struct{} // closed when the connection attempt or the connection has ended
	checking bool          // a look for the stick is running
	declined string        // a stick whose password question the user cancelled, until it is removed
	webLogin bool          // a sign-in to the web page is running
}

func (a *trayApp) ui() appUI { return appUI{a.shell.dialogs(), a} }

func tooltip(s wingui.IconState, plain string) string {
	switch s {
	case wingui.Connected:
		return "CryptStorage: connected (" + plain + ")"
	case wingui.Connecting:
		return "CryptStorage: connecting..."
	}
	return "CryptStorage: not connected"
}

// setState must be called with a.mu held.
func (a *trayApp) setState(s wingui.IconState) {
	a.state = s
	a.shell.show(s, tooltip(s, a.plain))
}

func (a *trayApp) notify(body string) {
	log.Print(body)
	a.shell.notify(body, strings.HasPrefix(body, "Warning") || strings.HasPrefix(body, "Syncing stopped"))
}

// firstStart turns starting at sign-in on the first time the tray runs, and says so. Later the menu
// decides; a user who turned it off is not overruled.
func (a *trayApp) firstStart() {
	dir, err := configDir()
	if err != nil {
		return
	}
	marker := filepath.Join(dir, "tray-autostart-set")
	if _, err := os.Stat(marker); err == nil {
		return
	}
	if err := a.shell.setAutostart(true); err != nil {
		log.Printf("autostart: %v", err)
		return
	}
	os.MkdirAll(dir, 0o700)                    //nolint
	os.WriteFile(marker, []byte("1\n"), 0o600) //nolint
	a.shell.menuChanged()
	a.notify("CryptStorage now starts when you sign in. You can turn this off in the menu of the padlock " + a.shell.iconPlace() + ".")
}

// serverLine names the server the tray uses, so a stale setting shows.
func serverLine() string {
	s := os.Getenv("CRYPTSTORAGE_SERVER")
	if s == "" {
		return "Server: not set"
	}
	return "Server: " + s
}

func (a *trayApp) menu() []menuItem {
	a.mu.Lock()
	defer a.mu.Unlock()
	status := "Not connected"
	switch a.state {
	case wingui.Connecting:
		status = "Connecting..."
	case wingui.Connected:
		status = "Connected: " + a.plain
	}
	items := []menuItem{{ID: menuStatus, Text: status, Disabled: true}, {}}
	if a.state == wingui.Connected {
		items = append(items, menuItem{ID: menuDisconnect, Text: "Disconnect"})
	} else {
		items = append(items, menuItem{ID: menuConnect, Text: "Connect", Disabled: a.state != wingui.Disconnected})
	}
	items = append(items, menuItem{ID: menuOpen, Text: "Open storage folder", Disabled: a.state != wingui.Connected})
	if dir := syncDir(); dir != "" {
		items = append(items, menuItem{ID: menuOpenSync, Text: "Open synchronised folder", Disabled: a.state != wingui.Connected})
	}
	return append(items,
		menuItem{},
		menuItem{ID: menuWebLogin, Text: "Open account web page...", Disabled: a.webLogin},
		menuItem{ID: menuAutostart, Text: "Start when I sign in", Toggle: true, Checked: a.shell.autostart()},
		menuItem{ID: menuSetup, Text: "Set up CryptStorage..."},
		menuItem{ID: menuServer, Text: "Change server...", Disabled: a.state != wingui.Disconnected || a.webLogin},
		menuItem{},
		menuItem{ID: menuServerLine, Text: serverLine(), Disabled: true},
		menuItem{ID: menuVersion, Text: "Version " + appVersion(), Disabled: true},
		menuItem{ID: menuExit, Text: "Exit"},
	)
}

func (a *trayApp) click(id int) {
	switch id {
	case menuConnect:
		a.mu.Lock()
		a.declined = ""
		a.mu.Unlock()
		a.connect(false)
	case menuDisconnect:
		a.disconnect(0)
	case menuOpen:
		a.mu.Lock()
		p := a.plain
		a.mu.Unlock()
		if p != "" {
			a.shell.openFolder(p) //nolint
		}
	case menuOpenSync:
		a.shell.openFolder(syncDir()) //nolint
	case menuWebLogin:
		a.openWebPage()
	case menuAutostart:
		if err := a.shell.setAutostart(!a.shell.autostart()); err != nil {
			a.ui().Error("Could not change the setting: " + err.Error())
		}
		a.shell.menuChanged()
	case menuSetup:
		if err := a.shell.startSetup(); err != nil {
			a.ui().Error("Could not start the setup: " + err.Error())
		}
	case menuServer:
		a.changeServer()
	case menuExit:
		a.disconnect(time.Minute)
		a.shell.quit()
	}
}

// openWebPage signs in to the account web page without typing the password into it: the
// questions are the tray's dialogs, the browser opens signed in. The stick is not needed.
func (a *trayApp) openWebPage() {
	a.mu.Lock()
	if a.webLogin {
		a.mu.Unlock()
		return
	}
	a.webLogin = true
	a.mu.Unlock()
	a.shell.menuChanged()
	defer func() {
		a.mu.Lock()
		a.webLogin = false
		a.mu.Unlock()
		a.shell.menuChanged()
	}()
	reloadEnvFile(envFilePath())
	ui := a.ui()
	ask := func(label string) string { s, _ := ui.Line(label); return s }
	if err := askServerWith(ask, ui.Error, probeServer,
		"Which server is your storage on? Your administrator gives you the address,\nfor example https://storage.example.com"); err != nil {
		if !errors.Is(err, tray.ErrCancelled) {
			ui.Error(err.Error())
		}
		return
	}
	webLoginDesktop(ui)
}

// changeServer moves the client to another server, after saying what that means for the stick.
func (a *trayApp) changeServer() {
	reloadEnvFile(envFilePath())
	ui := a.ui()
	now := os.Getenv("CRYPTSTORAGE_SERVER")
	if now == "" {
		now = "(none)"
	}
	if !ui.Confirm("Server now: " + now + "\n\n" + serverChangeNote + "\n\nChange the server?") {
		return
	}
	ask := func(label string) string { s, _ := ui.Line(label); return s }
	err := changeServer(ask, ui.Error, probeServer, "New server address, for example https://storage.example.com")
	switch {
	case err == nil:
		a.notify("Server changed to " + os.Getenv("CRYPTSTORAGE_SERVER") + ".")
	case !errors.Is(err, tray.ErrCancelled) && !errors.Is(err, errNoServer):
		ui.Error(err.Error())
	}
}

// lookForStick connects when a CryptStorage stick is plugged in (or already there at start). A stick the
// user said no to is not asked about again until it has been taken out.
func (a *trayApp) lookForStick() {
	a.mu.Lock()
	if a.state != wingui.Disconnected || a.checking {
		a.mu.Unlock()
		return
	}
	a.checking = true
	a.mu.Unlock()
	dev, err := usb.FindCryptDevice()
	a.mu.Lock()
	a.checking = false
	if err != nil {
		a.declined = ""
		a.mu.Unlock()
		return
	}
	declined := dev.Path == a.declined
	a.mu.Unlock()
	if !declined {
		a.connect(true)
	}
}

// connect runs the connect flow and then keeps the storage open until the stick is removed or
// Disconnect is chosen. auto: started by plugging in the stick.
func (a *trayApp) connect(auto bool) {
	a.mu.Lock()
	if a.state != wingui.Disconnected {
		a.mu.Unlock()
		return
	}
	stop, done := make(chan struct{}), make(chan struct{})
	a.stop, a.done = stop, done
	a.setState(wingui.Connecting)
	a.mu.Unlock()
	defer close(done)
	reloadEnvFile(envFilePath()) // the server may have been changed in a terminal meanwhile

	ui := a.ui()
	devicePath, err := a.open(ui, stop)
	a.mu.Lock()
	a.plain = ""
	a.stop = nil
	if auto && errors.Is(err, tray.ErrCancelled) {
		a.declined = devicePath
	}
	a.setState(wingui.Disconnected)
	a.mu.Unlock()
	if err != nil && !errors.Is(err, tray.ErrCancelled) {
		log.Print(err)
		ui.Error(err.Error())
	}
}

// open connects and stays connected; it returns the stick's device when it was found.
func (a *trayApp) open(ui appUI, stop chan struct{}) (string, error) {
	ask := func(label string) string { s, _ := ui.Line(label); return s }
	if err := askServerWith(ask, ui.Error, probeServer,
		"Which server is your storage on? Your administrator gives you the address,\nfor example https://storage.example.com"); err != nil {
		return "", err
	}
	devicePath, err := findStick()
	if err != nil {
		return "", err
	}
	select {
	case <-stop: // Exit was chosen while looking for the stick
		return devicePath, tray.ErrCancelled
	default:
	}
	st, err := trayOpen(ui, devicePath)
	if err != nil {
		return devicePath, err
	}
	a.mu.Lock()
	a.plain = openVolume.plain
	a.setState(wingui.Connected)
	a.mu.Unlock()
	trayConnected(ui, st)
	removed := false
	stayConnected(st.device, stop, func(r bool) { removed = r })
	if removed {
		ui.Notify("The stick was removed: storage disconnected.")
	} else {
		ui.Notify("Storage disconnected.")
	}
	return devicePath, nil
}

// disconnect closes the storage if it is open (or stops a connection being made) and waits up to
// wait for it to finish. With wait 0 it does not wait.
func (a *trayApp) disconnect(wait time.Duration) {
	a.mu.Lock()
	stop, done := a.stop, a.done
	a.stop = nil
	a.mu.Unlock()
	if stop == nil {
		return
	}
	close(stop)
	if wait > 0 {
		select {
		case <-done:
		case <-time.After(wait):
			log.Print("disconnect did not finish in time")
		}
	}
}
