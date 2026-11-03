// testapp signs in like `cryptclient connect` does with a passkey, for tests/browser/passkey.mjs: it
// prints "OPEN <address>" instead of starting a browser, so the test's Chromium approves the sign-in,
// and then "WEB <address>", the web UI signed in with a ticket like `cryptclient web-login` opens.
// Settings come from the environment: API_URL, CRYPTSTORAGE_USER, CRYPTSTORAGE_PASSWORD.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"cryptclient/apiclient"
	"cryptclient/browserlogin"
	"cryptclient/e2ee"
)

func main() {
	if err := run(); err != nil {
		fmt.Println("FAILED:", err)
		os.Exit(1)
	}
	fmt.Println("SIGNED IN")
}

func run() error {
	user := os.Getenv("CRYPTSTORAGE_USER")
	api := apiclient.New(os.Getenv("API_URL"), "", "")
	info, err := api.ServerInfo()
	if err != nil {
		return err
	}
	ks, err := e2ee.DeriveSet(info.KdfSalt, user, os.Getenv("CRYPTSTORAGE_PASSWORD"))
	if err != nil {
		return err
	}
	if _, err := api.LoginKeys(user, ks.Current.AuthKey, ks.LegacyAuthKey(), ""); !errors.Is(err, apiclient.ErrTOTPRequired) {
		return fmt.Errorf("expected the second factor to be asked for, got %v", err)
	}
	pk, err := api.PasskeyBeginKeys(user, ks.Current.AuthKey, ks.LegacyAuthKey())
	if err != nil {
		return err
	}
	err = browserlogin.Approve(context.Background(),
		browserlogin.Request{ApproveURL: pk.ApproveURL, Options: pk.Options, Username: user},
		func(page string) error { fmt.Println("OPEN " + page); return nil },
		func(string) {},
		func(cred json.RawMessage) error { return api.PasskeyFinish(pk.Session, cred) })
	if err != nil {
		return err
	}
	if _, err := api.E2EEStorage(); err != nil {
		var apiErr *apiclient.APIError
		if errors.As(err, &apiErr) && apiErr.Status == 401 {
			return fmt.Errorf("the token from the passkey sign-in was refused: %w", err)
		}
	}
	// then hand the sign-in to the web UI, as `cryptclient web-login` does
	t, err := api.WebTicket()
	if err != nil {
		return fmt.Errorf("web ticket: %w", err)
	}
	fmt.Println("WEB " + t.URL)
	return nil
}
