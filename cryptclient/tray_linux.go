package main

import (
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"cryptclient/appdir"
	"cryptclient/sni"
	"cryptclient/tray"
	"cryptclient/wingui"
)

// The Linux tray: `cryptclient tray` (the application menu, starting at sign-in, or after the setup)
// puts the padlock in the panel's tray area (StatusNotifierItem, package sni) and stays running. The
// shared part is tray_app.go; here are the zenity dialogs, notify-send notifications, the look for a
// plugged-in stick and starting at sign-in (XDG autostart).
//
// The udev rule still starts `cryptclient tray --auto-connect` for an inserted stick. When this tray
// runs, that one leaves the stick to it (trayRunning); otherwise it asks once, as before.

func hasConsole() bool { return true }

func cmdTrayWindows() {}

// trayLockPath is the file the running tray holds a lock on, one per user.
func trayLockPath() string {
	if dir := os.Getenv("XDG_RUNTIME_DIR"); dir != "" {
		return filepath.Join(dir, "cryptstorage-tray.lock")
	}
	return filepath.Join(os.TempDir(), fmt.Sprintf("cryptstorage-tray-%d.lock", os.Getuid()))
}

// lockTray takes the lock; the returned file holds it until the program ends. ok is false when
// another tray holds it.
func lockTray() (f *os.File, ok bool) {
	f, err := os.OpenFile(trayLockPath(), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		log.Printf("tray lock: %v", err)
		return nil, true // better two trays than none
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		f.Close()
		return nil, false
	}
	return f, true
}

// trayRunning tells whether this user's tray is running.
func trayRunning() bool {
	f, ok := lockTray()
	if f != nil {
		f.Close() // releases the lock
	}
	return !ok
}

// cmdTrayDesktop runs the tray until Exit is chosen or the session ends. It returns false, having
// done nothing, when this session cannot show it (no graphical session, zenity or session bus).
func cmdTrayDesktop() bool {
	d, ok := tray.NewDialogs()
	if !ok {
		return false
	}
	lock, ok := lockTray()
	if !ok {
		tray.Notify(appTitle, "CryptStorage is already running: its padlock is in the panel.")
		return true
	}
	defer lock.Close()
	logToFile()

	shell := &linuxShell{d: d, quitCh: make(chan struct{})}
	a := &trayApp{shell: shell}
	t, err := sni.Start(sni.Config{
		ID:      "cryptstorage",
		Title:   "CryptStorage",
		Menu:    func() []sni.MenuItem { return sniMenu(a.menu()) },
		OnClick: a.click,
	}, linuxIcon(wingui.Disconnected), tooltip(wingui.Disconnected, ""))
	if errors.Is(err, sni.ErrNoSession) {
		log.Print(err)
		return false
	}
	if err != nil {
		d.Error("Could not show the CryptStorage icon: " + err.Error())
		os.Exit(1)
	}
	defer t.Close()
	shell.mu.Lock()
	shell.tray = t
	shell.mu.Unlock()

	// signing out ends the program with SIGTERM: close the storage first
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)
	go func() {
		<-sigs
		a.disconnect(15 * time.Second)
		shell.quit()
	}()

	a.firstStart()
	time.AfterFunc(3*time.Second, func() {
		if !t.Visible() {
			a.notify("Your desktop does not show tray icons, so the CryptStorage padlock is not visible " +
				"(on GNOME, the AppIndicator extension shows them). CryptStorage still asks for the password " +
				"when you plug in the stick.")
		}
	})
	go watchSticks(shell.quitCh, a.lookForStick)
	a.lookForStick() // the stick may be in already
	<-shell.quitCh
	return true
}

// linuxShell is the padlock in the panel.
type linuxShell struct {
	d      *tray.Dialogs
	mu     sync.Mutex
	tray   *sni.Tray
	quitCh chan struct{}
	once   sync.Once
}

func (l *linuxShell) dialogs() trayDialogs { return l.d }

func (l *linuxShell) show(s wingui.IconState, tip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.tray != nil {
		l.tray.Set(linuxIcon(s), tip) // also tells the desktop that the menu changed
	}
}

func (l *linuxShell) notify(body string, warning bool) {
	args := []string{"-a", appTitle, "-i", "drive-harddisk"}
	if warning {
		args = append(args, "-u", "critical")
	}
	exec.Command("notify-send", append(args, appTitle, body)...).Run() //nolint
}

func (l *linuxShell) menuChanged() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.tray != nil {
		l.tray.MenuChanged()
	}
}

func (l *linuxShell) quit() { l.once.Do(func() { close(l.quitCh) }) }

func (l *linuxShell) openFolder(path string) error { return exec.Command("xdg-open", path).Start() }

func (l *linuxShell) iconPlace() string { return "in the panel" }

// linuxIcon is the padlock in the sizes the panels ask for.
func linuxIcon(s wingui.IconState) []sni.Pixmap {
	var out []sni.Pixmap
	for _, size := range []int{16, 22, 24, 32, 48, 64} {
		out = append(out, sni.PixmapOf(wingui.DrawIcon(s, size)))
	}
	return out
}

func sniMenu(items []menuItem) []sni.MenuItem {
	out := make([]sni.MenuItem, len(items))
	for i, it := range items {
		out[i] = sni.MenuItem{ID: it.ID, Text: it.Text, Toggle: it.Toggle, Checked: it.Checked, Disabled: it.Disabled}
	}
	return out
}

// watchSticks calls found when a USB disk appears or one of its partitions is mounted (the desktop
// mounts a stick a moment after it is plugged in, and a key file can be read only then). Removals and
// the client's own mounts do not count, so a stick the user disconnected is not asked about again.
func watchSticks(quit <-chan struct{}, found func()) {
	seen := blockState()
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-quit:
			return
		case <-tick.C:
		}
		now := blockState()
		for k := range now {
			if !seen[k] {
				go found()
				break
			}
		}
		seen = now
	}
}

// blockState is the set of disks (/sys/block) and of mounted disk partitions.
func blockState() map[string]bool {
	s := map[string]bool{}
	if entries, err := os.ReadDir("/sys/block"); err == nil {
		for _, e := range entries {
			s["disk "+e.Name()] = true
		}
	}
	if b, err := os.ReadFile("/proc/self/mounts"); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			if f := strings.Fields(line); len(f) > 1 && strings.HasPrefix(f[0], "/dev/") {
				s["mount "+f[0]+" "+f[1]] = true
			}
		}
	}
	return s
}

// logToFile sends what the tray prints to ~/.cache/cryptstorage/tray.log, as on Windows: started from the
// panel or at sign-in it has nowhere else to print, and the log is what a help request needs.
func logToFile() {
	dir, err := os.UserCacheDir()
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
	unix.Dup3(int(f.Fd()), 2, 0) //nolint // a crash trace goes to file descriptor 2
	log.SetOutput(f)
	log.Printf("CryptStorage tray %s started", appVersion())
}

// autostartFile is the XDG autostart entry that starts the tray at sign-in. An older version's entry
// (secdisk-tray.desktop) is renamed, so that the setting stays as the user left it.
func autostartFile() string {
	dir := os.Getenv("XDG_CONFIG_HOME")
	if dir == "" {
		home, _ := os.UserHomeDir()
		dir = filepath.Join(home, ".config")
	}
	p := filepath.Join(dir, "autostart", "cryptstorage-tray.desktop")
	if _, err := os.Lstat(p); os.IsNotExist(err) {
		os.Rename(filepath.Join(dir, "autostart", appdir.Legacy+"-tray.desktop"), p) //nolint
	}
	return p
}

func (l *linuxShell) autostart() bool {
	b, err := os.ReadFile(autostartFile())
	return err == nil && !strings.Contains(string(b), "\nHidden=true")
}

func (l *linuxShell) setAutostart(on bool) error {
	p := autostartFile()
	if !on {
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	entry := "[Desktop Entry]\nType=Application\nName=CryptStorage\n" +
		"Comment=Opens your encrypted storage when the key stick is plugged in\n" +
		"Exec=" + desktopQuote(exe) + " tray\nIcon=drive-harddisk\nTerminal=false\nNoDisplay=true\n" +
		"X-GNOME-Autostart-enabled=true\n"
	return os.WriteFile(p, []byte(entry), 0o600)
}

// desktopQuote quotes a path for a desktop entry's Exec line when it needs it.
func desktopQuote(s string) string {
	if !strings.ContainsAny(s, " \t\"'\\$`") {
		return s
	}
	return `"` + strings.NewReplacer(`\`, `\\\\`, `"`, `\\"`, "`", "\\\\`", "$", `\\$`).Replace(s) + `"`
}

// startSetup opens the guided setup (cryptclient setup) in a terminal, which stays open at the end so
// its last lines can be read.
func (l *linuxShell) startSetup() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	script := shellQuote(exe) + ` setup; echo; read -r -p "Press Enter to close this window." _`
	for _, t := range [][]string{
		{"x-terminal-emulator", "-e"}, // Debian and Ubuntu: the desktop's own terminal
		{"gnome-terminal", "--"},
		{"konsole", "-e"},
		{"xfce4-terminal", "-x"},
		{"xterm", "-e"},
	} {
		if p, err := exec.LookPath(t[0]); err == nil {
			cmd := exec.Command(p, append(t[1:], "bash", "-c", script)...)
			if err := cmd.Start(); err != nil {
				return err
			}
			return cmd.Process.Release()
		}
	}
	return errors.New("no terminal program was found; run `cryptclient setup` in a terminal")
}

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

// startTrayAfterSetup starts the tray when it is not running yet, so the padlock appears (and turns on
// starting at sign-in) once the setup is done. Best effort; not as root (sudo) or without a desktop.
func startTrayAfterSetup() {
	if os.Geteuid() == 0 || (os.Getenv("DISPLAY") == "" && os.Getenv("WAYLAND_DISPLAY") == "") {
		return
	}
	if _, err := exec.LookPath("zenity"); err != nil || trayRunning() {
		return
	}
	exe, err := os.Executable()
	if err != nil {
		return
	}
	cmd := exec.Command(exe, "tray")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true} // not ended with this terminal
	if cmd.Start() == nil {
		cmd.Process.Release() //nolint
		fmt.Println("The CryptStorage padlock is now in the panel: it asks for the password when the stick is plugged in.")
	}
}
