package wingui

import (
	"errors"
	"runtime"
	"strings"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ErrCancelled means the user pressed Cancel or closed the window.
var ErrCancelled = errors.New("cancelled")

const promptClass = "cryptstoragePrompt"

// prompt is one open question window.
type prompt struct {
	edit   windows.Handle
	answer string
	ok     bool
	done   bool
}

var (
	promptOnce  sync.Once
	promptErr   error
	promptsMu   sync.Mutex
	openPrompts = map[windows.Handle]*prompt{}

	// promptShown is called with the window once it is up (tests answer it from there).
	promptShown func(windows.Handle)
)

// Prompt asks for one line of text in a small window: a password when secret is set (shown as dots),
// otherwise e.g. a username or a code. Enter answers, Esc cancels. The answer is returned as typed.
func Prompt(title, label string, secret bool) (string, error) {
	setup()
	promptOnce.Do(func() { promptErr = registerClass(promptClass, windows.NewCallback(promptProc)) })
	if promptErr != nil {
		return "", promptErr
	}
	// A window belongs to the thread that made it, and only that thread gets its messages.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	scale := func(v int32) int32 { return v * dpi() / 96 }
	font := messageFont()
	if font != 0 {
		defer pDeleteObject.Call(font) //nolint
	}
	label = strings.TrimRight(label, " ")
	pad, width := scale(14), scale(380)
	textW := width - 2*pad
	labelH := textHeight(label, font, textW)
	editH, btnW, btnH := scale(24), scale(88), scale(28)
	clientH := pad + labelH + scale(8) + editH + scale(16) + btnH + pad

	style := uint32(wsOverlapped | wsCaption | wsSysMenu)
	exStyle := uint32(wsExDlgModalFrame | wsExTopmost | wsExControlParent)
	r := rect{0, 0, width, clientH}
	pAdjustWindowRectEx.Call(uintptr(unsafe.Pointer(&r)), uintptr(style), 0, uintptr(exStyle)) //nolint
	w, h := r.Right-r.Left, r.Bottom-r.Top
	sw, _, _ := pGetSystemMetrics.Call(smCxScreen)
	sh, _, _ := pGetSystemMetrics.Call(smCyScreen)
	hwnd, err := createWindow(exStyle, promptClass, title, style, (int32(sw)-w)/2, (int32(sh)-h)/3, w, h, 0, 0)
	if err != nil {
		return "", err
	}
	p := &prompt{}
	promptsMu.Lock()
	openPrompts[hwnd] = p
	promptsMu.Unlock()
	defer func() {
		promptsMu.Lock()
		delete(openPrompts, hwnd)
		promptsMu.Unlock()
	}()

	y := pad
	controls := []windows.Handle{}
	add := func(h windows.Handle, err error) windows.Handle {
		if err == nil {
			controls = append(controls, h)
		}
		return h
	}
	add(createWindow(0, "STATIC", label, wsChild|wsVisible|ssLeft|ssNoPrefix, pad, y, textW, labelH, hwnd, 0))
	y += labelH + scale(8)
	editStyle := uint32(wsChild | wsVisible | wsTabStop | wsGroup | esAutoHScroll)
	if secret {
		editStyle |= esPassword
	}
	p.edit = add(createWindow(wsExClientEdge, "EDIT", "", editStyle, pad, y, textW, editH, hwnd, idEdit))
	y += editH + scale(16)
	add(createWindow(0, "BUTTON", "OK", wsChild|wsVisible|wsTabStop|wsGroup|bsDefPushButton,
		width-pad-2*btnW-scale(8), y, btnW, btnH, hwnd, idOK))
	add(createWindow(0, "BUTTON", "Cancel", wsChild|wsVisible|wsTabStop|bsPushButton,
		width-pad-btnW, y, btnW, btnH, hwnd, idCancel))
	if font != 0 {
		for _, c := range controls {
			pSendMessageW.Call(uintptr(c), wmSetFont, font, 1) //nolint
		}
	}

	pShowWindow.Call(uintptr(hwnd), swShow)  //nolint
	pSetForegroundWindow.Call(uintptr(hwnd)) //nolint
	pSetFocus.Call(uintptr(p.edit))          //nolint
	if promptShown != nil {
		go promptShown(hwnd)
	}

	var m msg
	for !p.done {
		r, _, _ := pGetMessageW.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
		if int32(r) <= 0 {
			break
		}
		// IsDialogMessage gives the window the keys of a dialog: Tab, Enter (OK) and Esc (Cancel).
		if d, _, _ := pIsDialogMessageW.Call(uintptr(hwnd), uintptr(unsafe.Pointer(&m))); d == 0 {
			pTranslateMessage.Call(uintptr(unsafe.Pointer(&m))) //nolint
			pDispatchMessageW.Call(uintptr(unsafe.Pointer(&m))) //nolint
		}
	}
	if !p.ok {
		return "", ErrCancelled
	}
	return p.answer, nil
}

func promptProc(hwnd windows.Handle, m uint32, wParam, lParam uintptr) uintptr {
	promptsMu.Lock()
	p := openPrompts[hwnd]
	promptsMu.Unlock()
	if p == nil {
		return defWindowProc(hwnd, m, wParam, lParam)
	}
	switch m {
	case dmGetDefID:
		return idOK | dcHasDefID<<16
	case wmCommand:
		switch loword(wParam) {
		case idOK:
			p.answer, p.ok = windowText(p.edit), true
			pSetWindowTextW.Call(uintptr(p.edit), uintptr(unsafe.Pointer(utf16("")))) //nolint
			pDestroyWindow.Call(uintptr(hwnd))                                        //nolint
			return 0
		case idCancel:
			pDestroyWindow.Call(uintptr(hwnd)) //nolint
			return 0
		}
	case wmClose:
		pDestroyWindow.Call(uintptr(hwnd)) //nolint
		return 0
	case wmDestroy:
		p.done = true
		// wakes the loop in Prompt, which may be waiting in GetMessage when the window was closed from outside
		pPostMessageW.Call(0, wmNull, 0, 0) //nolint
		return 0
	}
	return defWindowProc(hwnd, m, wParam, lParam)
}

// textHeight is the height the label needs when wrapped to width.
func textHeight(text string, font uintptr, width int32) int32 {
	dc, _, _ := pGetDC.Call(0)
	if dc == 0 {
		return 40
	}
	defer pReleaseDC.Call(0, dc) //nolint
	if font != 0 {
		old, _, _ := pSelectObject.Call(dc, font)
		defer pSelectObject.Call(dc, old) //nolint
	}
	r := rect{0, 0, width, 0}
	pDrawTextW.Call(dc, uintptr(unsafe.Pointer(utf16(text))), ^uintptr(0), uintptr(unsafe.Pointer(&r)), //nolint
		dtCalcRect|dtWordBreak|dtNoPrefix)
	if r.Bottom < 16 {
		return 16
	}
	return r.Bottom
}
