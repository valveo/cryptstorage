package wingui

import (
	"errors"
	"runtime"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

// MenuItem is one line of the tray menu. An item with an empty Text is a separator.
type MenuItem struct {
	ID       int
	Text     string
	Checked  bool
	Disabled bool
}

// TrayConfig says what the tray shows and whom it tells about clicks and events. The callbacks run on
// their own goroutines, so they may open dialogs; OnEndSession is the exception, see there.
type TrayConfig struct {
	Menu    func() []MenuItem // the menu, built again for each click
	OnClick func(id int)
	// OnVolumeArrived is called when Windows reports a new drive (a USB stick was plugged in).
	OnVolumeArrived func()
	// OnEndSession is called when the user signs out or Windows shuts down. It must finish quickly:
	// Windows ends the program a few seconds later.
	OnEndSession func()
	// Ready is called once the icon is up.
	Ready func(*Tray)
}

// Tray is the icon next to the clock.
type Tray struct {
	cfg            TrayConfig
	hwnd           windows.Handle
	mu             sync.Mutex
	icon           uintptr
	tip            string
	taskbarCreated uint32
}

const (
	trayClass    = "cryptstorageTray"
	trayCallback = wmApp + 1
	trayIconID   = 1

	nimAdd        = 0
	nimModify     = 1
	nimDelete     = 2
	nimSetVersion = 4
	nifMessage    = 0x01
	nifIcon       = 0x02
	nifTip        = 0x04
	nifInfo       = 0x10
	nifShowTip    = 0x80
	niifInfo      = 0x1
	niifWarning   = 0x2
	ninSelect     = wmUser
	ninKeySelect  = wmUser + 1
	notifyIconV4  = 4

	mfString    = 0x0
	mfGrayed    = 0x1
	mfChecked   = 0x8
	mfSeparator = 0x800
	tpmReturn   = 0x0100
	tpmRightBtn = 0x0002
)

type notifyIconData struct {
	Size            uint32
	Wnd             windows.Handle
	ID              uint32
	Flags           uint32
	CallbackMessage uint32
	Icon            uintptr
	Tip             [128]uint16
	State           uint32
	StateMask       uint32
	Info            [256]uint16
	Version         uint32
	InfoTitle       [64]uint16
	InfoFlags       uint32
	GUIDItem        windows.GUID
	BalloonIcon     uintptr
}

var theTray *Tray // one per process; the window procedure finds it here

// RunTray shows the icon and handles its events until Quit is called. It blocks, and the icon belongs
// to the goroutine that runs it.
func RunTray(cfg TrayConfig, icon uintptr, tip string) error {
	setup()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if theTray != nil {
		return errors.New("the tray is already running")
	}
	if err := registerClass(trayClass, windows.NewCallback(trayProc)); err != nil {
		return err
	}
	t := &Tray{cfg: cfg, icon: icon, tip: tip}
	r, _, _ := pRegisterWindowMessageW.Call(uintptr(unsafe.Pointer(utf16("TaskbarCreated"))))
	t.taskbarCreated = uint32(r)
	theTray = t
	// A top-level window that is never shown: only those get the drive arrival broadcasts (a
	// message-only window would not).
	hwnd, err := createWindow(0, trayClass, "CryptStorage", wsOverlapped, 0, 0, 0, 0, 0, 0)
	if err != nil {
		return err
	}
	t.hwnd = hwnd
	if err := t.add(); err != nil {
		pDestroyWindow.Call(uintptr(hwnd)) //nolint
		return err
	}
	if cfg.Ready != nil {
		go cfg.Ready(t)
	}
	var m msg
	for {
		r, _, _ := pGetMessageW.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
		if int32(r) <= 0 {
			return nil
		}
		pTranslateMessage.Call(uintptr(unsafe.Pointer(&m))) //nolint
		pDispatchMessageW.Call(uintptr(unsafe.Pointer(&m))) //nolint
	}
}

func (t *Tray) data(flags uint32) *notifyIconData {
	d := &notifyIconData{Wnd: t.hwnd, ID: trayIconID, Flags: flags}
	d.Size = uint32(unsafe.Sizeof(*d))
	return d
}

func copyUTF16(dst []uint16, s string) {
	u, _ := windows.UTF16FromString(s[:indexNUL(s)])
	if len(u) > len(dst) {
		u = u[:len(dst)]
		u[len(u)-1] = 0
	}
	copy(dst, u)
}

func notifyIcon(op uintptr, d *notifyIconData) error {
	if r, _, err := pShellNotifyIconW.Call(op, uintptr(unsafe.Pointer(d))); r == 0 {
		return err
	}
	return nil
}

// add puts the icon in the notification area (again, after Explorer restarted).
func (t *Tray) add() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	d := t.data(nifMessage | nifIcon | nifTip | nifShowTip)
	d.CallbackMessage = trayCallback
	d.Icon = t.icon
	copyUTF16(d.Tip[:], t.tip)
	if err := notifyIcon(nimAdd, d); err != nil {
		return err
	}
	d.Version = notifyIconV4
	return notifyIcon(nimSetVersion, d)
}

// Set changes the icon and its tooltip. The tray does not free the old icon.
func (t *Tray) Set(icon uintptr, tip string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.icon, t.tip = icon, tip
	d := t.data(nifIcon | nifTip | nifShowTip)
	d.Icon = icon
	copyUTF16(d.Tip[:], tip)
	notifyIcon(nimModify, d) //nolint
}

// Notify shows a notification next to the icon (a toast on Windows 10 and 11).
func (t *Tray) Notify(title, text string, warning bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	d := t.data(nifInfo)
	copyUTF16(d.InfoTitle[:], title)
	copyUTF16(d.Info[:], text)
	d.InfoFlags = niifInfo
	if warning {
		d.InfoFlags = niifWarning
	}
	notifyIcon(nimModify, d) //nolint
}

// Quit removes the icon and makes RunTray return.
func (t *Tray) Quit() {
	pPostMessageW.Call(uintptr(t.hwnd), wmClose, 0, 0) //nolint
}

func (t *Tray) showMenu() {
	if t.cfg.Menu == nil {
		return
	}
	menu, _, _ := pCreatePopupMenu.Call()
	if menu == 0 {
		return
	}
	defer pDestroyMenu.Call(menu) //nolint
	for _, it := range t.cfg.Menu() {
		if it.Text == "" {
			pAppendMenuW.Call(menu, mfSeparator, 0, 0) //nolint
			continue
		}
		flags := uintptr(mfString)
		if it.Checked {
			flags |= mfChecked
		}
		if it.Disabled {
			flags |= mfGrayed
		}
		pAppendMenuW.Call(menu, flags, uintptr(it.ID), uintptr(unsafe.Pointer(utf16(it.Text)))) //nolint
	}
	var pt point
	pGetCursorPos.Call(uintptr(unsafe.Pointer(&pt))) //nolint
	// Without these two calls the menu does not close when the user clicks elsewhere (documented quirk
	// of TrackPopupMenu for notification icons).
	pSetForegroundWindow.Call(uintptr(t.hwnd)) //nolint
	id, _, _ := pTrackPopupMenu.Call(menu, tpmReturn|tpmRightBtn, uintptr(pt.X), uintptr(pt.Y), 0, uintptr(t.hwnd), 0)
	pPostMessageW.Call(uintptr(t.hwnd), wmNull, 0, 0) //nolint
	if id != 0 && t.cfg.OnClick != nil {
		go t.cfg.OnClick(int(id))
	}
}

func trayProc(hwnd windows.Handle, m uint32, wParam, lParam uintptr) uintptr {
	t := theTray
	if t == nil || (t.hwnd != 0 && hwnd != t.hwnd) {
		return defWindowProc(hwnd, m, wParam, lParam)
	}
	switch m {
	case trayCallback:
		switch loword(lParam) {
		case wmContextMenu, ninSelect, ninKeySelect: // right click, left click, keyboard
			t.showMenu()
		}
		return 0
	case wmDeviceChange:
		if wParam == dbtDeviceArrive && t.cfg.OnVolumeArrived != nil {
			go t.cfg.OnVolumeArrived()
		}
		return 1
	case wmQueryEndSess:
		return 1
	case wmEndSession:
		if wParam != 0 && t.cfg.OnEndSession != nil {
			t.cfg.OnEndSession()
		}
		return 0
	case wmClose:
		notifyIcon(nimDelete, t.data(0))   //nolint
		pDestroyWindow.Call(uintptr(hwnd)) //nolint
		return 0
	case wmDestroy:
		pPostQuitMessage.Call(0) //nolint
		return 0
	}
	if t.taskbarCreated != 0 && m == t.taskbarCreated {
		t.add() //nolint
		return 0
	}
	return defWindowProc(hwnd, m, wParam, lParam)
}
