//go:build linux

// Package sni puts an icon in the Linux desktop's tray area: a StatusNotifierItem with a dbusmenu
// menu over the session D-Bus, which KDE, Xfce, Cinnamon, LXQt and Ubuntu's GNOME (AppIndicator
// extension) show. Pure Go, no GTK: the same role as package wingui's tray on Windows.
//
// Specifications: https://www.freedesktop.org/wiki/Specifications/StatusNotifierItem/ and
// libdbusmenu's com.canonical.dbusmenu interface.
package sni

import (
	"errors"
	"fmt"
	"image"
	"os"
	"reflect"
	"strings"
	"sync"

	"github.com/godbus/dbus/v5"
	"github.com/godbus/dbus/v5/introspect"
	"github.com/godbus/dbus/v5/prop"
)

const (
	itemIface    = "org.kde.StatusNotifierItem"
	itemPath     = dbus.ObjectPath("/StatusNotifierItem")
	menuIface    = "com.canonical.dbusmenu"
	menuPath     = dbus.ObjectPath("/MenuBar")
	watcherName  = "org.kde.StatusNotifierWatcher"
	watcherPath  = dbus.ObjectPath("/StatusNotifierWatcher")
	separatorIDs = 100000 // separators get ids from here; the menu's own ids are smaller
)

// MenuItem is one line of the menu. An item with an empty Text is a separator.
type MenuItem struct {
	ID       int
	Text     string
	Toggle   bool // a check box; Checked tells whether it is ticked
	Checked  bool
	Disabled bool
}

// Config says what the icon shows and whom it tells about clicks.
type Config struct {
	ID      string            // the application's id, e.g. "cryptstorage"
	Title   string            // shown by some desktops next to the icon or in their settings
	Menu    func() []MenuItem // the menu, built again whenever it may have changed
	OnClick func(id int)      // called on its own goroutine
}

// Tray is the icon. Its methods may be called from any goroutine.
type Tray struct {
	cfg   Config
	conn  *dbus.Conn
	name  string
	props *prop.Properties

	mu       sync.Mutex
	revision uint32
	served   []MenuItem // the menu as the desktop last saw it
	visible  bool       // a desktop tray area took the icon
	closed   bool
}

// Pixmap is one size of the icon, in the format the specification wants: ARGB32, network byte order.
type Pixmap struct {
	Width, Height int32
	Data          []byte
}

// PixmapOf converts an image.
func PixmapOf(img *image.NRGBA) Pixmap {
	b := img.Bounds()
	data := make([]byte, 0, b.Dx()*b.Dy()*4)
	for y := b.Min.Y; y < b.Max.Y; y++ {
		for x := b.Min.X; x < b.Max.X; x++ {
			c := img.NRGBAAt(x, y)
			data = append(data, c.A, c.R, c.G, c.B)
		}
	}
	return Pixmap{Width: int32(b.Dx()), Height: int32(b.Dy()), Data: data}
}

// tooltip is the ToolTip property: icon name, icon pixmaps, title, text.
type tooltip struct {
	IconName string
	Icon     []Pixmap
	Title    string
	Text     string
}

// ErrNoSession means there is no session bus to talk to (no graphical session).
var ErrNoSession = errors.New("no D-Bus session bus")

// Start shows the icon. It fails only when there is no session bus; a desktop without a tray area
// is not an error (see Visible), and the icon appears if one starts later.
func Start(cfg Config, icon []Pixmap, tip string) (*Tray, error) {
	conn, err := dbus.ConnectSessionBus()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNoSession, err)
	}
	t := &Tray{cfg: cfg, conn: conn, name: fmt.Sprintf("org.kde.StatusNotifierItem-%d-1", os.Getpid())}
	if err := t.export(icon, tip); err != nil {
		conn.Close()
		return nil, err
	}
	if _, err := conn.RequestName(t.name, dbus.NameFlagDoNotQueue); err != nil {
		conn.Close()
		return nil, fmt.Errorf("D-Bus name %s: %w", t.name, err)
	}
	// a tray area that starts (or restarts) later takes the icon then
	conn.AddMatchSignal(dbus.WithMatchInterface("org.freedesktop.DBus"), //nolint
		dbus.WithMatchMember("NameOwnerChanged"), dbus.WithMatchArg(0, watcherName))
	signals := make(chan *dbus.Signal, 8)
	conn.Signal(signals)
	go func() {
		for s := range signals {
			if s.Name == "org.freedesktop.DBus.NameOwnerChanged" && len(s.Body) == 3 {
				if owner, _ := s.Body[2].(string); owner != "" {
					t.register()
				} else {
					t.setVisible(false)
				}
			}
		}
	}()
	t.register()
	return t, nil
}

func (t *Tray) export(icon []Pixmap, tip string) error {
	ro := func(v any) *prop.Prop { return &prop.Prop{Value: v, Emit: prop.EmitFalse} }
	props, err := prop.Export(t.conn, itemPath, prop.Map{
		itemIface: {
			"Category":            ro("ApplicationStatus"),
			"Id":                  ro(t.cfg.ID),
			"Title":               ro(t.cfg.Title),
			"Status":              ro("Active"),
			"WindowId":            ro(int32(0)),
			"IconName":            ro(""),
			"IconThemePath":       ro(""),
			"IconPixmap":          ro(icon),
			"OverlayIconName":     ro(""),
			"OverlayIconPixmap":   ro([]Pixmap{}),
			"AttentionIconName":   ro(""),
			"AttentionIconPixmap": ro([]Pixmap{}),
			"AttentionMovieName":  ro(""),
			"ToolTip":             ro(tooltip{Icon: []Pixmap{}, Title: t.cfg.Title, Text: tip}),
			"ItemIsMenu":          ro(true), // a click opens the menu, as on Windows
			"Menu":                ro(menuPath),
		},
	})
	if err != nil {
		return err
	}
	t.props = props
	if err := t.conn.Export(itemMethods{t}, itemPath, itemIface); err != nil {
		return err
	}
	menuProps, err := prop.Export(t.conn, menuPath, prop.Map{
		menuIface: {
			"Version":       ro(uint32(3)),
			"TextDirection": ro("ltr"),
			"Status":        ro("normal"),
			"IconThemePath": ro([]string{}),
		},
	})
	if err != nil {
		return err
	}
	if err := t.conn.Export(menuMethods{t}, menuPath, menuIface); err != nil {
		return err
	}
	node := func(iface string, methods any, p *prop.Properties) string {
		n := &introspect.Node{Interfaces: []introspect.Interface{
			introspect.IntrospectData, prop.IntrospectData,
			{Name: iface, Methods: introspect.Methods(methods), Properties: p.Introspection(iface)},
		}}
		return string(introspect.NewIntrospectable(n))
	}
	if err := t.conn.Export(introspect.Introspectable(node(itemIface, itemMethods{t}, props)), itemPath,
		"org.freedesktop.DBus.Introspectable"); err != nil {
		return err
	}
	return t.conn.Export(introspect.Introspectable(node(menuIface, menuMethods{t}, menuProps)), menuPath,
		"org.freedesktop.DBus.Introspectable")
}

// register hands the icon to the desktop's tray area, if there is one.
func (t *Tray) register() {
	err := t.conn.Object(watcherName, watcherPath).Call(watcherName+".RegisterStatusNotifierItem", 0, t.name).Err
	t.setVisible(err == nil)
}

func (t *Tray) setVisible(v bool) {
	t.mu.Lock()
	t.visible = v
	t.mu.Unlock()
}

// Visible tells whether a tray area has taken the icon. Without one (e.g. GNOME without the
// AppIndicator extension) nothing is shown, but everything else still works.
func (t *Tray) Visible() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.visible
}

// Set changes the icon and its tooltip.
func (t *Tray) Set(icon []Pixmap, tip string) {
	t.props.SetMust(itemIface, "IconPixmap", icon)
	t.props.SetMust(itemIface, "ToolTip", tooltip{Icon: []Pixmap{}, Title: t.cfg.Title, Text: tip})
	t.emit(itemPath, itemIface+".NewIcon")
	t.emit(itemPath, itemIface+".NewToolTip")
	t.MenuChanged()
}

// MenuChanged tells the desktop to read the menu again if it changed. It calls cfg.Menu on its own
// goroutine, so it may be called with the caller's own locks held.
func (t *Tray) MenuChanged() {
	go func() {
		items := t.cfg.Menu()
		t.mu.Lock()
		if reflect.DeepEqual(items, t.served) {
			t.mu.Unlock()
			return
		}
		t.revision++
		rev := t.revision
		t.mu.Unlock()
		t.emit(menuPath, menuIface+".LayoutUpdated", rev, int32(0))
	}()
}

func (t *Tray) emit(path dbus.ObjectPath, name string, values ...any) {
	t.mu.Lock()
	closed := t.closed
	t.mu.Unlock()
	if !closed {
		t.conn.Emit(path, name, values...) //nolint
	}
}

// Close removes the icon.
func (t *Tray) Close() {
	t.mu.Lock()
	t.closed = true
	t.mu.Unlock()
	t.conn.Close() //nolint
}

// itemMethods are the StatusNotifierItem's methods. With ItemIsMenu the desktop opens the menu
// itself; these are here for desktops that call them anyway.
type itemMethods struct{ t *Tray }

func (itemMethods) Activate(x, y int32) *dbus.Error          { return nil }
func (itemMethods) SecondaryActivate(x, y int32) *dbus.Error { return nil }
func (itemMethods) ContextMenu(x, y int32) *dbus.Error       { return nil }
func (itemMethods) Scroll(delta int32, dir string) *dbus.Error {
	return nil
}

// layout is one menu entry as GetLayout sends it: (ia{sv}av).
type layout struct {
	ID       int32
	Props    map[string]dbus.Variant
	Children []dbus.Variant
}

// menuMethods is the com.canonical.dbusmenu interface.
type menuMethods struct{ t *Tray }

// GetLayout sends the whole menu: it is small, so parentID and depth are not needed.
func (m menuMethods) GetLayout(parentID int32, depth int32, names []string) (uint32, layout, *dbus.Error) {
	items := m.t.cfg.Menu()
	m.t.mu.Lock()
	m.t.served = items
	rev := m.t.revision
	m.t.mu.Unlock()
	root := layout{ID: 0, Props: map[string]dbus.Variant{"children-display": dbus.MakeVariant("submenu")},
		Children: []dbus.Variant{}}
	if parentID != 0 {
		for i, it := range items {
			if itemID(i, it) == parentID {
				return rev, layout{ID: parentID, Props: itemProps(it), Children: []dbus.Variant{}}, nil
			}
		}
		return rev, layout{}, dbus.MakeFailedError(fmt.Errorf("no menu item %d", parentID))
	}
	for i, it := range items {
		root.Children = append(root.Children,
			dbus.MakeVariant(layout{ID: itemID(i, it), Props: itemProps(it), Children: []dbus.Variant{}}))
	}
	return rev, root, nil
}

func itemID(i int, it MenuItem) int32 {
	if it.Text == "" {
		return int32(separatorIDs + i)
	}
	return int32(it.ID)
}

func itemProps(it MenuItem) map[string]dbus.Variant {
	if it.Text == "" {
		return map[string]dbus.Variant{"type": dbus.MakeVariant("separator")}
	}
	p := map[string]dbus.Variant{
		// an underscore marks the access key; a path or name may contain real ones
		"label":   dbus.MakeVariant(strings.ReplaceAll(it.Text, "_", "__")),
		"enabled": dbus.MakeVariant(!it.Disabled),
		"visible": dbus.MakeVariant(true),
	}
	if it.Toggle {
		state := int32(0)
		if it.Checked {
			state = 1
		}
		p["toggle-type"] = dbus.MakeVariant("checkmark")
		p["toggle-state"] = dbus.MakeVariant(state)
	}
	return p
}

type groupProps struct {
	ID    int32
	Props map[string]dbus.Variant
}

func (m menuMethods) GetGroupProperties(ids []int32, names []string) ([]groupProps, *dbus.Error) {
	items := m.t.cfg.Menu()
	var out []groupProps
	for i, it := range items {
		id := itemID(i, it)
		if len(ids) == 0 || containsID(ids, id) {
			out = append(out, groupProps{ID: id, Props: itemProps(it)})
		}
	}
	return out, nil
}

func (m menuMethods) GetProperty(id int32, name string) (dbus.Variant, *dbus.Error) {
	for i, it := range m.t.cfg.Menu() {
		if itemID(i, it) == id {
			if v, ok := itemProps(it)[name]; ok {
				return v, nil
			}
		}
	}
	return dbus.Variant{}, dbus.MakeFailedError(fmt.Errorf("no property %s on menu item %d", name, id))
}

func (m menuMethods) Event(id int32, event string, data dbus.Variant, timestamp uint32) *dbus.Error {
	if event == "clicked" && id > 0 && id < separatorIDs && m.t.cfg.OnClick != nil {
		go m.t.cfg.OnClick(int(id))
	}
	return nil
}

type menuEvent struct {
	ID        int32
	Event     string
	Data      dbus.Variant
	Timestamp uint32
}

func (m menuMethods) EventGroup(events []menuEvent) ([]int32, *dbus.Error) {
	for _, e := range events {
		m.Event(e.ID, e.Event, e.Data, e.Timestamp) //nolint
	}
	return []int32{}, nil
}

// AboutToShow tells the desktop to read the menu again when it changed since it last did.
func (m menuMethods) AboutToShow(id int32) (bool, *dbus.Error) {
	items := m.t.cfg.Menu()
	m.t.mu.Lock()
	defer m.t.mu.Unlock()
	return !reflect.DeepEqual(items, m.t.served), nil
}

func (m menuMethods) AboutToShowGroup(ids []int32) ([]int32, []int32, *dbus.Error) {
	need, _ := m.AboutToShow(0)
	if need {
		return []int32{0}, []int32{}, nil
	}
	return []int32{}, []int32{}, nil
}

func containsID(ids []int32, id int32) bool {
	for _, x := range ids {
		if x == id {
			return true
		}
	}
	return false
}
