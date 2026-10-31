package apiclient

import (
	"encoding/json"
	"errors"
)

// PasskeyStart from POST /auth/passkey/begin: the browser's options, a one-time session token that
// stays with this program, and the web page that asks for the passkey.
type PasskeyStart struct {
	Options    json.RawMessage `json:"options"`
	Session    string          `json:"session"`
	ApproveURL string          `json:"approve_url"`
}

// ErrNoPasskey means the account has no passkey, or the server does not offer passkeys.
var ErrNoPasskey = errors.New("no passkey for this account")

// PasskeyBegin checks the password again and starts a passkey sign-in.
func (c *Client) PasskeyBegin(username, password string) (*PasskeyStart, error) {
	var r PasskeyStart
	err := c.post("/auth/passkey/begin", map[string]string{"username": username, "password": password}, &r)
	var apiErr *APIError
	if errors.As(err, &apiErr) && (apiErr.Status == 404 || apiErr.Status == 503) {
		return nil, ErrNoPasskey
	}
	if err != nil {
		return nil, err
	}
	return &r, nil
}

// PasskeyFinish sends the browser's answer and logs in like Login.
func (c *Client) PasskeyFinish(session string, credential json.RawMessage) error {
	var resp LoginResponse
	if err := c.post("/auth/passkey/finish", map[string]any{"session": session, "credential": credential}, &resp); err != nil {
		return err
	}
	c.Token = resp.AccessToken
	c.RefreshToken = resp.RefreshToken
	return nil
}

// WebTicket from POST /auth/web/ticket: a one-time ticket that signs the web UI in without the
// password, and the web UI address that takes it.
type WebTicket struct {
	Ticket    string `json:"ticket"`
	URL       string `json:"url"`
	ExpiresIn int    `json:"expires_in"`
}

// WebTicket hands this sign-in over to the web UI. Call it right after logging in: the server wants
// the second factor to be recent.
func (c *Client) WebTicket() (*WebTicket, error) {
	var r WebTicket
	if err := c.post("/auth/web/ticket", nil, &r); err != nil {
		return nil, err
	}
	return &r, nil
}
