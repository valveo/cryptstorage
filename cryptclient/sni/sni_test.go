//go:build linux

package sni

import (
	"bufio"
	"image"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
)

// privateBus starts a session bus of the test's own (dbus-daemon), so the test does not need a
// desktop. Skipped when dbus-daemon is not installed.
func privateBus(t *testing.T) {
	t.Helper()
	daemon, err := exec.LookPath("dbus-daemon")
	if err != nil {
		t.Skip("dbus-daemon not installed")
	}
	cmd := exec.Command(daemon, "--session", "--nofork", "--print-address=1")
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() }) //nolint
	addr, err := bufio.NewReader(out).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("DBUS_SESSION_BUS_ADDRESS", strings.TrimSpace(addr))
}

// watcher plays the desktop's tray area.
type watcher struct {
	mu    sync.Mutex
	items []string
}

func (w *watcher) RegisterStatusNotifierItem(service string) *dbus.Error {
	w.mu.Lock()
	w.items = append(w.items, service)
	w.mu.Unlock()
	return nil
}

func (w *watcher) registered() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]string(nil), w.items...)
}

func startWatcher(t *testing.T) (*dbus.Conn, *watcher) {
	t.Helper()
	conn, err := dbus.ConnectSessionBus()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	w := &watcher{}
	if err := conn.Export(w, watcherPath, watcherName); err != nil {
		t.Fatal(err)
	}
	if r, err := conn.RequestName(watcherName, dbus.NameFlagDoNotQueue); err != nil || r != dbus.RequestNameReplyPrimaryOwner {
		t.Fatalf("watcher name: %v %v", r, err)
	}
	return conn, w
}

func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	for end := time.Now().Add(5 * time.Second); time.Now().Before(end); time.Sleep(20 * time.Millisecond) {
		if ok() {
			return
		}
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestTrayShowsIconAndMenu(t *testing.T) {
	privateBus(t)
	host, w := startWatcher(t)

	var mu sync.Mutex
	connected := false
	clicks := make(chan int, 4)
	menu := func() []MenuItem {
		mu.Lock()
		defer mu.Unlock()
		status := "Not connected"
		if connected {
			status = "Connected: /media/me/my_files"
		}
		return []MenuItem{
			{ID: 1, Text: status, Disabled: true},
			{},
			{ID: 2, Text: "Connect"},
			{ID: 3, Text: "Start when I sign in", Toggle: true, Checked: true},
		}
	}
	icon := []Pixmap{PixmapOf(image.NewNRGBA(image.Rect(0, 0, 16, 16)))}
	tr, err := Start(Config{ID: "cryptstorage", Title: "CryptStorage", Menu: menu, OnClick: func(id int) { clicks <- id }},
		icon, "CryptStorage: not connected")
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Close()

	waitFor(t, "the icon to be registered", func() bool { return len(w.registered()) == 1 })
	waitFor(t, "Visible", tr.Visible)
	service := w.registered()[0]
	item := host.Object(service, itemPath)

	v, err := item.GetProperty(itemIface + ".ToolTip")
	if err != nil || !strings.Contains(v.String(), "CryptStorage: not connected") {
		t.Errorf("tooltip = %v, %v", v, err)
	}
	if v, err := item.GetProperty(itemIface + ".Menu"); err != nil || v.Value() != menuPath {
		t.Errorf("menu path = %v, %v", v, err)
	}
	if v, err := item.GetProperty(itemIface + ".IconPixmap"); err != nil || !strings.Contains(v.Signature().String(), "a(iiay)") {
		t.Errorf("icon = %v, %v", v.Signature(), err)
	}

	m := host.Object(service, menuPath)
	var rev uint32
	var root layout
	if err := m.Call(menuIface+".GetLayout", 0, int32(0), int32(-1), []string{}).Store(&rev, &root); err != nil {
		t.Fatal(err)
	}
	if len(root.Children) != 4 {
		t.Fatalf("menu has %d entries, want 4", len(root.Children))
	}
	entry := func(i int) layout {
		var l layout
		if err := dbus.Store([]any{root.Children[i].Value()}, &l); err != nil {
			t.Fatal(err)
		}
		return l
	}
	if l := entry(0); l.Props["label"].Value() != "Not connected" || l.Props["enabled"].Value() != false {
		t.Errorf("status entry = %v", l.Props)
	}
	if l := entry(1); l.Props["type"].Value() != "separator" {
		t.Errorf("separator entry = %v", l.Props)
	}
	if l := entry(3); l.Props["toggle-type"].Value() != "checkmark" || l.Props["toggle-state"].Value() != int32(1) {
		t.Errorf("check box entry = %v", l.Props)
	}

	// a click reaches OnClick
	if err := m.Call(menuIface+".Event", 0, int32(2), "clicked", dbus.MakeVariant(""), uint32(0)).Err; err != nil {
		t.Fatal(err)
	}
	select {
	case id := <-clicks:
		if id != 2 {
			t.Errorf("clicked %d, want 2", id)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the click did not arrive")
	}
	// a click on a separator or on nothing does not
	m.Call(menuIface+".Event", 0, int32(separatorIDs+1), "clicked", dbus.MakeVariant(""), uint32(0)) //nolint
	m.Call(menuIface+".Event", 0, int32(0), "clicked", dbus.MakeVariant(""), uint32(0))              //nolint

	// a changed state tells the desktop to read the menu again, with the underscore kept
	if err := host.AddMatchSignal(dbus.WithMatchInterface(menuIface), dbus.WithMatchMember("LayoutUpdated")); err != nil {
		t.Fatal(err)
	}
	signals := make(chan *dbus.Signal, 8)
	host.Signal(signals)
	mu.Lock()
	connected = true
	mu.Unlock()
	tr.Set(icon, "CryptStorage: connected")
	select {
	case s := <-signals:
		for s.Name != menuIface+".LayoutUpdated" {
			s = <-signals
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no LayoutUpdated after the menu changed")
	}
	var again bool
	if err := m.Call(menuIface+".AboutToShow", 0, int32(0)).Store(&again); err != nil || !again {
		t.Errorf("AboutToShow = %v, %v; want true before the new menu was read", again, err)
	}
	if err := m.Call(menuIface+".GetLayout", 0, int32(0), int32(-1), []string{}).Store(&rev, &root); err != nil {
		t.Fatal(err)
	}
	if l := entry(0); l.Props["label"].Value() != "Connected: /media/me/my__files" {
		t.Errorf("status entry = %v", l.Props["label"])
	}
	if err := m.Call(menuIface+".AboutToShow", 0, int32(0)).Store(&again); err != nil || again {
		t.Errorf("AboutToShow = %v, %v; want false after the menu was read", again, err)
	}
	select {
	case id := <-clicks:
		t.Errorf("unexpected click %d", id)
	default:
	}
}

func TestTrayWithoutTrayArea(t *testing.T) {
	privateBus(t)
	tr, err := Start(Config{ID: "cryptstorage", Menu: func() []MenuItem { return nil }}, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Close()
	if tr.Visible() {
		t.Error("Visible without a tray area")
	}
	// the tray area starts later: the icon is handed to it
	_, w := startWatcher(t)
	waitFor(t, "the icon to be registered", func() bool { return len(w.registered()) == 1 })
	waitFor(t, "Visible", tr.Visible)
}

func TestNoSessionBus(t *testing.T) {
	t.Setenv("DBUS_SESSION_BUS_ADDRESS", "unix:path=/nonexistent/bus")
	if _, err := Start(Config{}, nil, ""); err == nil {
		t.Error("Start without a bus succeeded")
	}
}
