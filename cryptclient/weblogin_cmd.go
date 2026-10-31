package main

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"golang.org/x/term"

	"cryptclient/apiclient"
	"cryptclient/browserlogin"
	"cryptclient/e2ee"
	"cryptclient/tray"
)

// cmdWebLogin signs in to the web UI without typing the password into it. The web UI comes from
// the server, so a password typed there is only as safe as the server; here the app signs in as usual
// (the password never leaves this computer, only the login key derived from it) and hands the web UI a
// one-time ticket. That web session manages the account; it cannot open the storage. No stick needed.
// Without a terminal (the app menu on Linux) it asks with desktop dialogs; the Windows tray has its own
// menu item.
func cmdWebLogin() {
	refuseElevated()
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		if d, ok := tray.NewDialogs(); ok {
			webLoginDesktop(d)
			return
		}
	}
	username := promptLine("Username: ")
	t, err := webLogin(terminal, username, func() (string, error) { return promptPassword("Password: "), nil })
	if err != nil {
		fatal("%v", err)
	}
	if err := browserlogin.OpenBrowser(t.URL); err != nil {
		fmt.Fprintf(os.Stderr, "Could not open the browser: %v\n", err)
	}
	fmt.Printf("The web page opens signed in. If it did not open, open this address within %d seconds "+
		"(it works once):\n%s\n", t.ExpiresIn, t.URL)
}

// webLoginDesktop runs the web sign-in with desktop dialogs (zenity, or the tray's windows).
func webLoginDesktop(d desktopUI) {
	username := savedUsername()
	if username == "" {
		var err error
		if username, err = d.Line("Username:"); err != nil {
			return
		}
	}
	t, err := webLogin(d, username, func() (string, error) { return d.Secret("Password for " + username + ":") })
	if errors.Is(err, tray.ErrCancelled) {
		return
	}
	if err != nil {
		d.Error(err.Error())
		return
	}
	if err := browserlogin.OpenBrowser(t.URL); err != nil {
		d.Error(fmt.Sprintf("Could not open the browser: %v\n\nOpen this address within %d seconds (it works once):\n%s",
			err, t.ExpiresIn, t.URL))
		return
	}
	d.Notify("Your account web page opens in the browser, signed in.")
}

// webLogin signs in as the app does (asking for the second factor with a) and returns the web UI's
// one-time ticket.
func webLogin(a asker, username string, password func() (string, error)) (*apiclient.WebTicket, error) {
	api := newAPI("")
	if _, err := checkE2EE(api); err != nil {
		return nil, err
	}
	if username = strings.TrimSpace(username); username == "" {
		return nil, errors.New("no username was typed")
	}
	pw, err := password()
	if err != nil {
		return nil, err
	}
	if pw == "" {
		return nil, errors.New("no password was typed")
	}
	keys, err := e2ee.Derive(username, pw)
	if err != nil {
		return nil, fmt.Errorf("could not derive keys: %v", err)
	}
	if err := loginWith(a, api, username, keys); err != nil {
		if errors.Is(err, tray.ErrCancelled) {
			return nil, err
		}
		return nil, fmt.Errorf("Login failed: %w", err)
	}
	t, err := api.WebTicket()
	if err != nil {
		return nil, fmt.Errorf("Could not sign in to the web page: %v", err)
	}
	if t.URL == "" {
		return nil, errors.New("The server does not know the address of its web page (BASE_URL is not set). Ask its administrator.")
	}
	return t, nil
}
