package main

import (
	"bufio"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
)

// The Linux tray end to end: the built client on a D-Bus session bus of the test's own, with the test
// as the desktop's tray area, zenity and notify-send replaced by scripts. No stick is plugged in.

type fakeWatcher struct {
	mu    sync.Mutex
	items []string
}

func (w *fakeWatcher) RegisterStatusNotifierItem(service string) *dbus.Error {
	w.mu.Lock()
	w.items = append(w.items, service)
	w.mu.Unlock()
	return nil
}

func (w *fakeWatcher) first() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.items) == 0 {
		return ""
	}
	return w.items[0]
}

type menuEntry struct {
	ID       int32
	Props    map[string]dbus.Variant
	Children []dbus.Variant
}

func eventually(t *testing.T, what string, ok func() bool) {
	t.Helper()
	for end := time.Now().Add(10 * time.Second); time.Now().Before(end); time.Sleep(50 * time.Millisecond) {
		if ok() {
			return
		}
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestLinuxTray(t *testing.T) {
	daemon, err := exec.LookPath("dbus-daemon")
	if err != nil {
		t.Skip("dbus-daemon not installed")
	}
	if testing.Short() {
		t.Skip("builds the client")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "cryptclient")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}

	// the bus and the tray area
	bus := exec.Command(daemon, "--session", "--nofork", "--print-address=1")
	out, _ := bus.StdoutPipe()
	if err := bus.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { bus.Process.Kill(); bus.Wait() }) //nolint
	addr, err := bufio.NewReader(out).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("DBUS_SESSION_BUS_ADDRESS", strings.TrimSpace(addr))
	host, err := dbus.ConnectSessionBus()
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close()
	w := &fakeWatcher{}
	host.Export(w, "/StatusNotifierWatcher", "org.kde.StatusNotifierWatcher") //nolint
	if _, err := host.RequestName("org.kde.StatusNotifierWatcher", dbus.NameFlagDoNotQueue); err != nil {
		t.Fatal(err)
	}

	// the desktop: dialogs answer Cancel, notifications are written down
	tools := filepath.Join(dir, "bin")
	os.MkdirAll(tools, 0o755) //nolint
	notes := filepath.Join(dir, "notes")
	os.WriteFile(filepath.Join(tools, "zenity"), []byte("#!/bin/sh\nexit 1\n"), 0o755)                         //nolint
	os.WriteFile(filepath.Join(tools, "notify-send"), []byte("#!/bin/sh\necho \"$@\" >> "+notes+"\n"), 0o755) //nolint
	home := filepath.Join(dir, "home")
	env := append(os.Environ(),
		"PATH="+tools+":/usr/bin:/bin", "DISPLAY=:99", "HOME="+home,
		"XDG_CONFIG_HOME="+filepath.Join(home, ".config"), "XDG_CACHE_HOME="+filepath.Join(home, ".cache"),
		"XDG_RUNTIME_DIR="+dir, "CRYPTSTORAGE_SERVER=", "CRYPTCLIENT_DEVICE=")
	run := func(args ...string) *exec.Cmd {
		c := exec.Command(bin, args...)
		c.Env = env
		return c
	}
	readNotes := func() string { b, _ := os.ReadFile(notes); return string(b) }

	tr := run("tray")
	if err := tr.Start(); err != nil {
		t.Fatal(err)
	}
	exited := make(chan error, 1)
	go func() { exited <- tr.Wait() }()
	defer tr.Process.Kill() //nolint

	eventually(t, "the icon in the tray area", func() bool { return w.first() != "" })
	menu := host.Object(w.first(), "/MenuBar")
	layout := func() map[string]map[string]any {
		var rev uint32
		var root menuEntry
		if err := menu.Call("com.canonical.dbusmenu.GetLayout", 0, int32(0), int32(-1), []string{}).Store(&rev, &root); err != nil {
			t.Fatal(err)
		}
		got := map[string]map[string]any{}
		for _, c := range root.Children {
			var e menuEntry
			dbus.Store([]any{c.Value()}, &e) //nolint
			if l, ok := e.Props["label"]; ok {
				p := map[string]any{"id": e.ID}
				for k, v := range e.Props {
					p[k] = v.Value()
				}
				got[l.Value().(string)] = p
			}
		}
		return got
	}
	click := func(id any) {
		if err := menu.Call("com.canonical.dbusmenu.Event", 0, id, "clicked", dbus.MakeVariant(""), uint32(0)).Err; err != nil {
			t.Fatal(err)
		}
	}

	// starting at sign-in is turned on the first time, and said so
	auto := filepath.Join(home, ".config", "autostart", "cryptstorage-tray.desktop")
	eventually(t, "the autostart entry", func() bool { _, err := os.Stat(auto); return err == nil })
	if b, _ := os.ReadFile(auto); !strings.Contains(string(b), "Exec="+bin+" tray\n") {
		t.Errorf("autostart entry:\n%s", b)
	}
	eventually(t, "the autostart notification", func() bool { return strings.Contains(readNotes(), "starts when you sign in") })

	m := layout()
	if m["Not connected"]["enabled"] != false || m["Connect"]["enabled"] != true {
		t.Errorf("menu while not connected: %v", m)
	}
	if m["Start when I sign in"]["toggle-type"] != "checkmark" || m["Start when I sign in"]["toggle-state"] != int32(1) {
		t.Errorf("autostart item: %v", m["Start when I sign in"])
	}
	if m["Open storage folder"]["enabled"] != false {
		t.Errorf("open folder enabled while not connected: %v", m["Open storage folder"])
	}

	// a second tray does not start; the udev rule's one leaves the stick to this one
	if err := run("tray").Run(); err != nil {
		t.Errorf("second tray: %v", err)
	}
	if !strings.Contains(readNotes(), "already running") {
		t.Errorf("second tray did not say it runs already: %q", readNotes())
	}
	if out, err := run("tray", "--auto-connect").CombinedOutput(); err != nil || !strings.Contains(string(out), "tray is running") {
		t.Errorf("udev tray: %v %s", err, out)
	}

	// the check box turns starting at sign-in off
	click(m["Start when I sign in"]["id"])
	eventually(t, "the autostart entry removed", func() bool { _, err := os.Stat(auto); return os.IsNotExist(err) })
	eventually(t, "the menu to show it", func() bool { return layout()["Start when I sign in"]["toggle-state"] == int32(0) })

	// Connect without a server asks for one; Cancel ends it quietly and the icon stays
	click(m["Connect"]["id"])
	time.Sleep(500 * time.Millisecond)
	eventually(t, "back to not connected", func() bool { return layout()["Not connected"] != nil })

	// Exit ends the program
	click(m["Exit"]["id"])
	select {
	case err := <-exited:
		if err != nil {
			t.Errorf("tray exited with %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Exit did not end the tray")
	}
	if log, _ := os.ReadFile(filepath.Join(home, ".cache", "cryptstorage", "tray.log")); !strings.Contains(string(log), "tray") {
		t.Errorf("tray.log: %q", log)
	}
}
