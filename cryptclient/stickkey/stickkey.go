// Package stickkey opens and seals the SSH key on the USB stick.
//
// A sealed key (crypto v3) needs the password and a stick secret that the server releases only after the
// full login, so a found or copied stick cannot be attacked offline. Older keys are protected by the
// password alone; the client seals them on the next connect.
package stickkey

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"cryptclient/crypto"
)

// API is what the server offers for stick secrets (apiclient.Client).
type API interface {
	CreateStick(name string) (string, []byte, error)
	StickSecret(stickID string) ([]byte, error)
}

// Sealed reports whether the key needs the server's stick secret.
func Sealed(blob []byte) bool {
	_, ok := crypto.StickID(blob)
	return ok
}

// Open decrypts the key: a sealed one with the stick secret from api (logged in), an older one with the
// password alone.
func Open(api API, blob []byte, password string) ([]byte, error) {
	id, ok := crypto.StickID(blob)
	if !ok {
		return crypto.DecryptKey(blob, password)
	}
	secret, err := api.StickSecret(formatID(id))
	if err != nil {
		return nil, err
	}
	defer wipe(secret)
	return crypto.DecryptSealed(blob, password, secret)
}

// Seal encrypts pem with the password and a new stick secret from api (logged in).
func Seal(api API, pem []byte, password, name string) ([]byte, error) {
	sid, secret, err := api.CreateStick(name)
	if err != nil {
		return nil, err
	}
	defer wipe(secret)
	id, err := parseID(sid)
	if err != nil {
		return nil, err
	}
	blob, err := crypto.EncryptSealed(pem, password, id, secret)
	if err != nil {
		return nil, err
	}
	// what goes on the stick must open again, before anything is overwritten
	if check, err := crypto.DecryptSealed(blob, password, secret); err != nil || string(check) != string(pem) {
		return nil, errors.New("the sealed key did not open again; nothing was changed")
	}
	return blob, nil
}

// Reseal encrypts pem for a new password, keeping the stick's id and secret (change-password).
func Reseal(api API, oldBlob, pem []byte, newPassword string) ([]byte, error) {
	id, ok := crypto.StickID(oldBlob)
	if !ok {
		return nil, errors.New("not a sealed key")
	}
	secret, err := api.StickSecret(formatID(id))
	if err != nil {
		return nil, err
	}
	defer wipe(secret)
	return crypto.EncryptSealed(pem, newPassword, id, secret)
}

// The server names sticks by UUID; the stick stores its 16 bytes.
// ID returns the stick's id on the server, for a sealed key.
func ID(blob []byte) (string, bool) {
	id, ok := crypto.StickID(blob)
	if !ok {
		return "", false
	}
	return formatID(id), true
}

func formatID(id [16]byte) string {
	h := hex.EncodeToString(id[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

func parseID(s string) ([16]byte, error) {
	var id [16]byte
	b, err := hex.DecodeString(strings.ReplaceAll(s, "-", ""))
	if err != nil || len(b) != 16 {
		return id, fmt.Errorf("the server sent an invalid stick id %q", s)
	}
	copy(id[:], b)
	return id, nil
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
