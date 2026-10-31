// Package wingui is the graphical side of the Windows client: the icon next to the clock (tray), the
// small windows that ask for a password or a code, message boxes and the start-at-sign-in setting.
// It talks to Windows directly (user32, shell32, gdi32), so the client stays one Go program without C
// code or a GUI library.
package wingui

import (
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	user32   = windows.NewLazySystemDLL("user32.dll")
	shell32  = windows.NewLazySystemDLL("shell32.dll")
	gdi32    = windows.NewLazySystemDLL("gdi32.dll")
	kernel32 = windows.NewLazySystemDLL("kernel32.dll")

	pAdjustWindowRectEx     = user32.NewProc("AdjustWindowRectEx")
	pAppendMenuW            = user32.NewProc("AppendMenuW")
	pCreateIconIndirect     = user32.NewProc("CreateIconIndirect")
	pCreatePopupMenu        = user32.NewProc("CreatePopupMenu")
	pCreateWindowExW        = user32.NewProc("CreateWindowExW")
	pDefWindowProcW         = user32.NewProc("DefWindowProcW")
	pDestroyIcon            = user32.NewProc("DestroyIcon")
	pDestroyMenu            = user32.NewProc("DestroyMenu")
	pDestroyWindow          = user32.NewProc("DestroyWindow")
	pDispatchMessageW       = user32.NewProc("DispatchMessageW")
	pDrawTextW              = user32.NewProc("DrawTextW")
	pGetCursorPos           = user32.NewProc("GetCursorPos")
	pGetDC                  = user32.NewProc("GetDC")
	pGetMessageW            = user32.NewProc("GetMessageW")
	pGetSystemMetrics       = user32.NewProc("GetSystemMetrics")
	pGetWindowTextLengthW   = user32.NewProc("GetWindowTextLengthW")
	pGetWindowTextW         = user32.NewProc("GetWindowTextW")
	pIsDialogMessageW       = user32.NewProc("IsDialogMessageW")
	pLoadCursorW            = user32.NewProc("LoadCursorW")
	pMessageBoxW            = user32.NewProc("MessageBoxW")
	pPostMessageW           = user32.NewProc("PostMessageW")
	pPostQuitMessage        = user32.NewProc("PostQuitMessage")
	pRegisterClassExW       = user32.NewProc("RegisterClassExW")
	pRegisterWindowMessageW = user32.NewProc("RegisterWindowMessageW")
	pReleaseDC              = user32.NewProc("ReleaseDC")
	pSendMessageW           = user32.NewProc("SendMessageW")
	pSetFocus               = user32.NewProc("SetFocus")
	pSetForegroundWindow    = user32.NewProc("SetForegroundWindow")
	pSetProcessDpiAwareCtx  = user32.NewProc("SetProcessDpiAwarenessContext")
	pSetWindowTextW         = user32.NewProc("SetWindowTextW")
	pShowWindow             = user32.NewProc("ShowWindow")
	pSystemParametersInfoW  = user32.NewProc("SystemParametersInfoW")
	pTrackPopupMenu         = user32.NewProc("TrackPopupMenu")
	pTranslateMessage       = user32.NewProc("TranslateMessage")

	pShellNotifyIconW = shell32.NewProc("Shell_NotifyIconW")
	pShellExecuteW    = shell32.NewProc("ShellExecuteW")

	pCreateBitmap       = gdi32.NewProc("CreateBitmap")
	pCreateDIBSection   = gdi32.NewProc("CreateDIBSection")
	pCreateFontIndirect = gdi32.NewProc("CreateFontIndirectW")
	pDeleteObject       = gdi32.NewProc("DeleteObject")
	pGetDeviceCaps      = gdi32.NewProc("GetDeviceCaps")
	pSelectObject       = gdi32.NewProc("SelectObject")

	pActivateActCtx   = kernel32.NewProc("ActivateActCtx")
	pCreateActCtxW    = kernel32.NewProc("CreateActCtxW")
	pGetModuleHandleW = kernel32.NewProc("GetModuleHandleW")
)

const (
	wmNull          = 0x0000
	wmDestroy       = 0x0002
	wmClose         = 0x0010
	wmQueryEndSess  = 0x0011
	wmEndSession    = 0x0016
	wmSetFont       = 0x0030
	wmContextMenu   = 0x007B
	wmCommand       = 0x0111
	wmDeviceChange  = 0x0219
	wmUser          = 0x0400
	wmApp           = 0x8000
	dmGetDefID      = wmUser
	dcHasDefID      = 0x534B
	dbtDeviceArrive = 0x8000

	wsOverlapped = 0x00000000
	wsPopup      = 0x80000000
	wsVisible    = 0x10000000
	wsChild      = 0x40000000
	wsCaption    = 0x00C00000
	wsSysMenu    = 0x00080000
	wsTabStop    = 0x00010000
	wsGroup      = 0x00020000
	wsBorder     = 0x00800000

	wsExDlgModalFrame = 0x00000001
	wsExTopmost       = 0x00000008
	wsExClientEdge    = 0x00000200
	wsExControlParent = 0x00010000

	esAutoHScroll   = 0x0080
	esPassword      = 0x0020
	bsPushButton    = 0x0000
	bsDefPushButton = 0x0001
	ssNoPrefix      = 0x0080
	ssLeft          = 0x0000

	idOK     = 1
	idCancel = 2
	idEdit   = 100

	swHide = 0
	swShow = 5

	colorBtnFace = 15
	idcArrow     = 32512

	dtWordBreak = 0x0010
	dtCalcRect  = 0x0400
	dtNoPrefix  = 0x0800

	smCxScreen = 0
	smCyScreen = 1
	smCxSmIcon = 49

	logPixelsY = 90

	mbOK          = 0x0
	mbYesNo       = 0x4
	mbIconError   = 0x10
	mbIconWarning = 0x30
	mbIconInfo    = 0x40
	mbTopmost     = 0x40000
	mbSetFg       = 0x10000
	idYes         = 6
)

type point struct{ X, Y int32 }

type rect struct{ Left, Top, Right, Bottom int32 }

type msg struct {
	Hwnd    windows.Handle
	Message uint32
	WParam  uintptr
	LParam  uintptr
	Time    uint32
	Pt      point
	Private uint32
}

type wndClassEx struct {
	Size       uint32
	Style      uint32
	WndProc    uintptr
	ClsExtra   int32
	WndExtra   int32
	Instance   windows.Handle
	Icon       windows.Handle
	Cursor     windows.Handle
	Background windows.Handle
	MenuName   *uint16
	ClassName  *uint16
	IconSm     windows.Handle
}

type logFont struct {
	Height, Width, Escapement, Orientation, Weight int32
	Italic, Underline, StrikeOut, CharSet          byte
	OutPrecision, ClipPrecision, Quality, PitchFam byte
	FaceName                                       [32]uint16
}

type nonClientMetrics struct {
	Size                         uint32
	BorderWidth                  int32
	ScrollWidth, ScrollHeight    int32
	CaptionWidth, CaptionHeight  int32
	CaptionFont                  logFont
	SmCaptionWidth, SmCaptionHgt int32
	SmCaptionFont                logFont
	MenuWidth, MenuHeight        int32
	MenuFont, StatusFont         logFont
	MessageFont                  logFont
	PaddedBorderWidth            int32
}

func utf16(s string) *uint16 {
	p, err := windows.UTF16PtrFromString(s)
	if err != nil { // a NUL inside the text: show it up to there
		p, _ = windows.UTF16PtrFromString(s[:indexNUL(s)])
	}
	return p
}

func indexNUL(s string) int {
	for i := 0; i < len(s); i++ {
		if s[i] == 0 {
			return i
		}
	}
	return len(s)
}

func moduleHandle() windows.Handle {
	h, _, _ := pGetModuleHandleW.Call(0)
	return windows.Handle(h)
}

var setupOnce sync.Once

// setup makes the windows look like other current Windows programs: the visual styles of the common
// controls (Windows' own manifest in shell32.dll, as a program without a manifest of its own can use)
// and sharp text on scaled displays. If either is missing the windows still work, they only look older.
func setup() {
	setupOnce.Do(func() {
		const dpiAwareSystem = ^uintptr(1) // DPI_AWARENESS_CONTEXT_SYSTEM_AWARE (-2)
		if pSetProcessDpiAwareCtx.Find() == nil {
			pSetProcessDpiAwareCtx.Call(dpiAwareSystem) //nolint
		}
		sys, err := windows.GetSystemDirectory()
		if err != nil {
			return
		}
		type actCtx struct {
			Size         uint32
			Flags        uint32
			Source       *uint16
			ProcArch     uint16
			LangID       uint16
			AssemblyDir  *uint16
			ResourceName uintptr
			AppName      *uint16
			Module       windows.Handle
		}
		const flagResourceName, flagSetProcessDefault = 0x008, 0x010
		ac := actCtx{Flags: flagResourceName | flagSetProcessDefault, Source: utf16(sys + `\shell32.dll`), ResourceName: 124}
		ac.Size = uint32(unsafe.Sizeof(ac))
		h, _, _ := pCreateActCtxW.Call(uintptr(unsafe.Pointer(&ac)))
		if h != uintptr(windows.InvalidHandle) {
			var cookie uintptr
			pActivateActCtx.Call(h, uintptr(unsafe.Pointer(&cookie))) //nolint
		}
	})
}

// dpi is the display scale the windows are laid out for (96 = 100 %).
func dpi() int32 {
	dc, _, _ := pGetDC.Call(0)
	if dc == 0 {
		return 96
	}
	defer pReleaseDC.Call(0, dc) //nolint
	d, _, _ := pGetDeviceCaps.Call(dc, logPixelsY)
	if d == 0 {
		return 96
	}
	return int32(d)
}

// messageFont is the font Windows uses in its own message boxes.
func messageFont() uintptr {
	var ncm nonClientMetrics
	ncm.Size = uint32(unsafe.Sizeof(ncm))
	const spiGetNonClientMetrics = 0x29
	if r, _, _ := pSystemParametersInfoW.Call(spiGetNonClientMetrics, uintptr(ncm.Size), uintptr(unsafe.Pointer(&ncm)), 0); r == 0 {
		return 0
	}
	f, _, _ := pCreateFontIndirect.Call(uintptr(unsafe.Pointer(&ncm.MessageFont)))
	return f
}

func registerClass(name string, proc uintptr) error {
	wc := wndClassEx{
		WndProc:    proc,
		Instance:   moduleHandle(),
		Background: colorBtnFace + 1,
		ClassName:  utf16(name),
	}
	wc.Size = uint32(unsafe.Sizeof(wc))
	cur, _, _ := pLoadCursorW.Call(0, idcArrow)
	wc.Cursor = windows.Handle(cur)
	if r, _, err := pRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc))); r == 0 {
		return err
	}
	return nil
}

func createWindow(exStyle uint32, class, text string, style uint32, x, y, w, h int32, parent windows.Handle, id uintptr) (windows.Handle, error) {
	r, _, err := pCreateWindowExW.Call(uintptr(exStyle), uintptr(unsafe.Pointer(utf16(class))),
		uintptr(unsafe.Pointer(utf16(text))), uintptr(style), uintptr(x), uintptr(y), uintptr(w), uintptr(h),
		uintptr(parent), id, uintptr(moduleHandle()), 0)
	if r == 0 {
		return 0, err
	}
	return windows.Handle(r), nil
}

func windowText(h windows.Handle) string {
	n, _, _ := pGetWindowTextLengthW.Call(uintptr(h))
	buf := make([]uint16, n+1)
	pGetWindowTextW.Call(uintptr(h), uintptr(unsafe.Pointer(&buf[0])), n+1) //nolint
	s := windows.UTF16ToString(buf)
	clear(buf)
	return s
}

func defWindowProc(h windows.Handle, m uint32, w, l uintptr) uintptr {
	r, _, _ := pDefWindowProcW.Call(uintptr(h), uintptr(m), w, l)
	return r
}

func loword(x uintptr) uint32 { return uint32(x) & 0xFFFF }

// MessageBox wrappers. They are shown on top of other windows, since the client has no window of its
// own for them to belong to.

// Error shows an error message and waits until it is closed.
func Error(title, text string) {
	setup()
	pMessageBoxW.Call(0, uintptr(unsafe.Pointer(utf16(text))), uintptr(unsafe.Pointer(utf16(title))), //nolint
		mbOK|mbIconError|mbTopmost|mbSetFg)
}

// Info shows a message and waits until it is closed.
func Info(title, text string) {
	setup()
	pMessageBoxW.Call(0, uintptr(unsafe.Pointer(utf16(text))), uintptr(unsafe.Pointer(utf16(title))), //nolint
		mbOK|mbIconInfo|mbTopmost|mbSetFg)
}

// Confirm asks a yes/no question. Closing the box is a no.
func Confirm(title, question string) bool {
	setup()
	r, _, _ := pMessageBoxW.Call(0, uintptr(unsafe.Pointer(utf16(question))), uintptr(unsafe.Pointer(utf16(title))),
		mbYesNo|mbIconWarning|mbTopmost|mbSetFg)
	return r == idYes
}

// Open opens a folder in Explorer, or an address in the browser.
func Open(target string) error {
	const swShowNormal = 1
	r, _, err := pShellExecuteW.Call(0, uintptr(unsafe.Pointer(utf16("open"))), uintptr(unsafe.Pointer(utf16(target))), 0, 0, swShowNormal)
	if r <= 32 {
		return err
	}
	return nil
}
