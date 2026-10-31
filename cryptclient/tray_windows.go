package main

import (
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"cryptclient/appdir"
	"cryptclient/deps"
	"cryptclient/tray"
	"cryptclient/wingui"
)

// The Windows tray: CryptStorage.exe (this program built as a window program, without a console) puts a
// padlock next to the clock. The shared part is tray_app.go; here are the windows, the notifications
// and the news of a plugged-in stick (WM_DEVICECHANGE).

const (
	trayExe   = "CryptStorage.exe"
	trayMutex = "cryptstorage-tray"
)

// hasConsole reports whether the program has a console window: false for CryptStorage.exe started from
// the Start menu or at sign-in, which then runs the tray.
func hasConsole() bool {
	h, _, _ := windows.NewLazySystemDLL("kernel32.dll").NewProc("GetConsoleWindow").Call()
	return h != 0
}

// winDialogs asks in windows.
type winDialogs struct{}

func (winDialogs) Line(label string) (string, error) {
	s, err := wingui.Prompt(appTitle, label, false)
	return strings.TrimSpace(s), cancelled(err)
}

// Secret is kept as typed: spaces belong to the password.
func (winDialogs) Secret(label string) (string, error) {
	s, err := wingui.Prompt(appTitle, label, true)
	return s, cancelled(err)
}

func (winDialogs) Confirm(question string) bool { return wingui.Confirm(appTitle, question) }
func (winDialogs) Error(msg string)             { wingui.Error(appTitle, msg) }

// cancelled maps the window's Cancel to the one the connect flow knows.
func cancelled(err error) error {
	if errors.Is(err, wingui.ErrCancelled) {
		return tray.ErrCancelled
	}
	return err
}

// winShell is the icon next to the clock.
type winShell struct {
	mu    sync.Mutex
	tray  *wingui.Tray // set once the icon is up
	icons map[wingui.IconState]uintptr
}

func (w *winShell) dialogs() trayDialogs { return winDialogs{} }

func (w *winShell) show(s wingui.IconState, tip string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.tray != nil {
		w.tray.Set(w.icons[s], tip)
	}
}

func (w *winShell) notify(body string, warning bool) {
	w.mu.Lock()
	t := w.tray
	w.mu.Unlock()
	if t != nil {
		t.Notify(appTitle, body, warning)
	}
}

func (w *winShell) menuChanged() {} // the menu is built for each click

func (w *winShell) quit() {
	w.mu.Lock()
	t := w.tray
	w.mu.Unlock()
	t.Quit()
}

func (w *winShell) openFolder(path string) error { return wingui.Open(path) }
func (w *winShell) autostart() bool              { return wingui.Autostart() }
func (w *winShell) setAutostart(on bool) error   { return wingui.SetAutostart(on) }
func (w *winShell) startSetup() error            { return startConsoleSetup() }
func (w *winShell) iconPlace() string            { return "next to the clock" }

func cmdTrayWindows() {
	logToFile()
	if deps.IsAdmin() {
		wingui.Error(appTitle, elevatedWarning)
		os.Exit(1)
	}
	if !wingui.SingleInstance(trayMutex) {
		wingui.Info(appTitle, "CryptStorage is already running: its padlock is next to the clock (perhaps behind the ^ arrow).")
		return
	}
	shell := &winShell{icons: map[wingui.IconState]uintptr{}}
	for _, s := range []wingui.IconState{wingui.Disconnected, wingui.Connecting, wingui.Connected} {
		h, err := wingui.Icon(s)
		if err != nil {
			log.Printf("icon: %v", err)
		}
		shell.icons[s] = h
	}
	a := &trayApp{shell: shell}
	err := wingui.RunTray(wingui.TrayConfig{
		Menu:            func() []wingui.MenuItem { return winMenu(a.menu()) },
		OnClick:         a.click,
		OnVolumeArrived: a.lookForStick,
		OnEndSession:    func() { a.disconnect(15 * time.Second) },
		Ready: func(t *wingui.Tray) {
			shell.mu.Lock()
			shell.tray = t
			shell.mu.Unlock()
			a.firstStart()
			a.lookForStick() // the stick may be in already (sign-in with the stick plugged in)
		},
	}, shell.icons[wingui.Disconnected], tooltip(wingui.Disconnected, ""))
	if err != nil {
		wingui.Error(appTitle, "Could not show the CryptStorage icon: "+err.Error())
		os.Exit(1)
	}
}

func winMenu(items []menuItem) []wingui.MenuItem {
	out := make([]wingui.MenuItem, len(items))
	for i, it := range items {
		out[i] = wingui.MenuItem{ID: it.ID, Text: it.Text, Checked: it.Checked, Disabled: it.Disabled}
	}
	return out
}

// logToFile sends what the client prints to %LOCALAPPDATA%\cryptstorage\tray.log: a window program has
// nowhere else to print, and the log is what a help request needs.
func logToFile() {
	dir, err := os.UserCacheDir() // %LOCALAPPDATA%
	if err != nil {
		return
	}
	p := filepath.Join(appdir.In(dir), "tray.log")
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return
	}
	if fi, err := os.Stat(p); err == nil && fi.Size() > 1<<20 {
		os.Rename(p, p+".old") //nolint
	}
	f, err := os.OpenFile(p, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return
	}
	os.Stdout, os.Stderr = f, f
	// a crash trace is written by the Go runtime to the process's standard error handle, not to
	// os.Stderr; without this a crash of the window program leaves no trace at all
	windows.SetStdHandle(windows.STD_ERROR_HANDLE, windows.Handle(f.Fd())) //nolint
	log.SetOutput(f)
	log.Printf("CryptStorage tray %s started", appVersion())
}

// startConsoleSetup opens the guided setup (cryptclient setup) in a console window of its own, which
// stays open at the end so its last lines can be read. A graphical setup app is planned (docs/design-setup-app.md).
//
// CreateProcess is called directly and not through os/exec: os/exec always hands the child standard
// handles (NUL when none are given, STARTF_USESTDHANDLES), and those win over the new console's own.
// cmd.exe then read its commands from NUL and closed at once, the setup's questions went to NUL, and
// clicking "Set up CryptStorage..." seemed to do nothing.
func startConsoleSetup() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	cli := filepath.Join(filepath.Dir(exe), "cryptclient.exe")
	if _, err := os.Stat(cli); err != nil {
		return fmt.Errorf("%s was not found", cli)
	}
	comspec := os.Getenv("ComSpec")
	if comspec == "" {
		comspec = filepath.Join(os.Getenv("SystemRoot"), "System32", "cmd.exe")
	}
	app, err := windows.UTF16PtrFromString(comspec)
	if err != nil {
		return err
	}
	// cmd /k removes the outermost quotes, hence the extra pair around the whole command
	line, err := windows.UTF16PtrFromString(`cmd.exe /k ""` + cli + `" setup"`)
	if err != nil {
		return err
	}
	dir, err := windows.UTF16PtrFromString(filepath.Dir(cli))
	if err != nil {
		return err
	}
	si := &windows.StartupInfo{Cb: uint32(unsafe.Sizeof(windows.StartupInfo{}))}
	var pi windows.ProcessInformation
	if err := windows.CreateProcess(app, line, nil, nil, false,
		windows.CREATE_NEW_CONSOLE|windows.CREATE_UNICODE_ENVIRONMENT, nil, dir, si, &pi); err != nil {
		return fmt.Errorf("starting %s: %w", comspec, err)
	}
	log.Printf("setup started in a console window (pid %d)", pi.ProcessId)
	windows.CloseHandle(pi.Thread)  //nolint
	windows.CloseHandle(pi.Process) //nolint
	return nil
}

// startTrayAfterSetup starts CryptStorage.exe from next to this program when it is not running yet, so the
// padlock appears (and turns on starting at sign-in) once the setup is done. Best effort.
func startTrayAfterSetup() {
	h, err := windows.OpenMutex(windows.SYNCHRONIZE, false, windows.StringToUTF16Ptr(`Local\`+trayMutex))
	if err == nil {
		windows.CloseHandle(h) //nolint
		return                 // already running
	}
	exe, err := os.Executable()
	if err != nil {
		return
	}
	tray := filepath.Join(filepath.Dir(exe), trayExe)
	if _, err := os.Stat(tray); err != nil {
		return
	}
	cmd := exec.Command(tray)
	if cmd.Start() == nil {
		cmd.Process.Release() //nolint
		fmt.Println("The CryptStorage padlock is now next to the clock: it asks for the password when the stick is plugged in.")
	}
}

// cmdTrayDesktop and trayRunning are the Linux tray's (cmdTray runs cmdTrayWindows here).
func cmdTrayDesktop() bool { return false }
func trayRunning() bool    { return false }
