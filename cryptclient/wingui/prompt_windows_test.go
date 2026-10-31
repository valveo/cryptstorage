package wingui

import (
	"errors"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var pGetDlgItem = user32.NewProc("GetDlgItem")

const wmSetText = 0x000C

// answerPrompt types text into the next prompt and presses OK (or Cancel when ok is false), as a user would.
func answerPrompt(t *testing.T, text string, ok bool) {
	t.Helper()
	promptShown = func(hwnd windows.Handle) {
		edit, _, _ := pGetDlgItem.Call(uintptr(hwnd), idEdit)
		if edit == 0 {
			t.Error("no input field in the window")
		}
		pSendMessageW.Call(edit, wmSetText, 0, uintptr(unsafe.Pointer(utf16(text)))) //nolint
		id := uintptr(idOK)
		if !ok {
			id = idCancel
		}
		pPostMessageW.Call(uintptr(hwnd), wmCommand, id, 0) //nolint
	}
	t.Cleanup(func() { promptShown = nil })
}

func withTimeout(t *testing.T, f func()) {
	t.Helper()
	done := make(chan struct{})
	go func() { defer close(done); f() }()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("the window did not close")
	}
}

func TestPromptAnswers(t *testing.T) {
	for _, secret := range []bool{false, true} {
		answerPrompt(t, " pass word ", true)
		withTimeout(t, func() {
			got, err := Prompt("CryptStorage test", "A long question that wraps over more than one line of the window, to see that the layout copes with it:", secret)
			if err != nil || got != " pass word " {
				t.Errorf("secret=%v: got %q, %v", secret, got, err)
			}
		})
	}
}

func TestPromptCancel(t *testing.T) {
	answerPrompt(t, "ignored", false)
	withTimeout(t, func() {
		if _, err := Prompt("CryptStorage test", "Username:", false); !errors.Is(err, ErrCancelled) {
			t.Errorf("got %v, want ErrCancelled", err)
		}
	})
}

func TestIcon(t *testing.T) {
	for _, s := range []IconState{Disconnected, Connecting, Connected} {
		h, err := Icon(s)
		if err != nil || h == 0 {
			t.Fatalf("state %d: %v", s, err)
		}
		FreeIcon(h)
	}
}
