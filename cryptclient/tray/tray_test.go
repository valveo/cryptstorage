//go:build !windows

package tray

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeZenity writes a script that records its arguments and answers like zenity would.
func fakeZenity(t *testing.T, script string) (*Dialogs, string) {
	t.Helper()
	dir := t.TempDir()
	args := filepath.Join(dir, "args")
	bin := filepath.Join(dir, "zenity")
	body := "#!/bin/sh\nprintf '%s\\n' \"$@\" > " + args + "\n" + script + "\n"
	if err := os.WriteFile(bin, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	return &Dialogs{zenity: bin}, args
}

func TestSecretKeepsSpaces(t *testing.T) {
	d, args := fakeZenity(t, `printf ' pass word \n'`)
	got, err := d.Secret("Password:")
	if err != nil || got != " pass word " {
		t.Fatalf("got %q, %v", got, err)
	}
	a, _ := os.ReadFile(args)
	if !strings.Contains(string(a), "--hide-text") {
		t.Fatalf("password dialog does not hide the text: %s", a)
	}
}

func TestCancel(t *testing.T) {
	d, _ := fakeZenity(t, "exit 1")
	if _, err := d.Line("Username:"); !errors.Is(err, ErrCancelled) {
		t.Fatalf("want ErrCancelled, got %v", err)
	}
	if d.Confirm("Trust?") {
		t.Fatal("a cancelled question counts as yes")
	}
}

func TestOtherFailureIsNotCancel(t *testing.T) {
	d, _ := fakeZenity(t, "exit 3")
	if _, err := d.Line("x"); err == nil || errors.Is(err, ErrCancelled) {
		t.Fatalf("want a zenity error, got %v", err)
	}
}

func TestConfirmYes(t *testing.T) {
	d, _ := fakeZenity(t, "exit 0")
	if !d.Confirm("Trust?") {
		t.Fatal("yes was not accepted")
	}
}

func TestMarkupEscaped(t *testing.T) {
	d, args := fakeZenity(t, "exit 0")
	d.Error("a <b> & c")
	a, _ := os.ReadFile(args)
	if !strings.Contains(string(a), "--text=a &lt;b&gt; &amp; c") {
		t.Fatalf("text not escaped: %s", a)
	}
}
