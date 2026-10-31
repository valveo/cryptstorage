package tray

// Desktop dialogs for the connect flow, so that it can run without a terminal: started from the
// application menu or by the udev rule when the stick is inserted (Linux, zenity). Windows has its own
// windows (package wingui); macOS still uses the terminal.

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

// ErrCancelled means the user closed a dialog or pressed Cancel.
var ErrCancelled = errors.New("cancelled")

const title = "CryptStorage"

// Dialogs asks questions with zenity.
type Dialogs struct {
	zenity string // path of the zenity binary
}

// NewDialogs returns the dialogs when this session can show them: Linux, a graphical session and
// zenity installed.
func NewDialogs() (*Dialogs, bool) {
	if runtime.GOOS != "linux" {
		return nil, false
	}
	if os.Getenv("DISPLAY") == "" && os.Getenv("WAYLAND_DISPLAY") == "" {
		return nil, false
	}
	p, err := exec.LookPath("zenity")
	if err != nil {
		return nil, false
	}
	return &Dialogs{zenity: p}, true
}

// run starts zenity and returns what it printed, without the final newline.
func (d *Dialogs) run(args ...string) (string, error) {
	out, err := exec.Command(d.zenity, append([]string{"--title=" + title}, args...)...).Output()
	var exit *exec.ExitError
	if errors.As(err, &exit) && exit.ExitCode() == 1 {
		return "", ErrCancelled
	}
	if err != nil {
		return "", fmt.Errorf("zenity: %w", err)
	}
	return strings.TrimSuffix(string(out), "\n"), nil
}

// Secret asks for a password. Only the newline zenity adds is removed: spaces belong to the password.
func (d *Dialogs) Secret(label string) (string, error) {
	return d.run("--entry", "--hide-text", "--text="+escape(label))
}

// Line asks for a line of text, e.g. a username or a verification code.
func (d *Dialogs) Line(label string) (string, error) {
	s, err := d.run("--entry", "--text="+escape(label))
	return strings.TrimSpace(s), err
}

// Confirm asks a yes/no question. Anything but an explicit yes is a no.
func (d *Dialogs) Confirm(question string) bool {
	_, err := d.run("--question", "--width=420", "--text="+escape(question))
	return err == nil
}

// Error shows an error and waits until the user closes it.
func (d *Dialogs) Error(msg string) {
	d.run("--error", "--width=420", "--text="+escape(msg)) //nolint
}

// Notify shows a desktop notification.
func (d *Dialogs) Notify(body string) {
	Notify(title, body)
}

// escape keeps zenity from reading the text as Pango markup (a fingerprint or an error message may
// contain & or <).
func escape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
}

// Notify shows a desktop notification (Linux: notify-send; Windows has its own in package wingui).
func Notify(title, body string) {
	exec.Command("notify-send", "-i", "drive-harddisk", title, body).Run() //nolint
}
