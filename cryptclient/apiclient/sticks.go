package apiclient

import (
	"encoding/hex"
	"errors"
)

// ErrStickRevoked means the server has no secret for this stick: it was removed from the account.
var ErrStickRevoked = errors.New("this stick was removed from your account, so its key can no longer be opened")

// ErrStickLocked means the stick was locked in the account (reported lost, or its removal was requested):
// its secret is not released until it is unlocked with the full sign-in (UnlockStick).
var ErrStickLocked = errors.New("this stick is locked in your account")

// ErrNoStickSecrets means the server does not offer stick secrets.
var ErrNoStickSecrets = errors.New("the server does not offer stick secrets")

type stickSecret struct {
	StickID string `json:"stick_id"`
	Secret  string `json:"secret"`
}

func (r stickSecret) decode() (string, []byte, error) {
	b, err := hex.DecodeString(r.Secret)
	if err != nil || len(b) != 32 {
		return "", nil, errors.New("the server sent an invalid stick secret")
	}
	return r.StickID, b, nil
}

func stickErr(err error) error {
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		switch {
		case apiErr.Status == 404 && apiErr.Detail == "STICK_REVOKED":
			return ErrStickRevoked
		case apiErr.Status == 403 && apiErr.Detail == "STICK_LOCKED":
			return ErrStickLocked
		case apiErr.Status == 503, apiErr.Status == 404 && apiErr.Detail == "Not Found":
			// off on this server, or a server from before stick secrets
			return ErrNoStickSecrets
		}
	}
	return err
}

// CreateStick asks for a new stick secret. name tells the user later which stick it is.
func (c *Client) CreateStick(name string) (stickID string, secret []byte, err error) {
	var r stickSecret
	if err := c.post("/users/me/sticks", map[string]string{"name": name}, &r); err != nil {
		return "", nil, stickErr(err)
	}
	return r.decode()
}

// StickSecret returns the secret of a sealed stick; it needs a session that passed the full login.
func (c *Client) StickSecret(stickID string) ([]byte, error) {
	var r stickSecret
	if err := c.post("/users/me/sticks/"+stickID+"/secret", nil, &r); err != nil {
		return nil, stickErr(err)
	}
	_, secret, err := r.decode()
	return secret, err
}

// UnlockStick unlocks a locked stick. It needs a session that passed the full login a moment ago;
// it also stops a waiting removal of the stick.
func (c *Client) UnlockStick(stickID string) error {
	return stickErr(c.post("/users/me/sticks/"+stickID+"/unlock", map[string]string{}, nil))
}
