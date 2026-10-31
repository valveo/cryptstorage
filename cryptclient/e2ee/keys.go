// Package e2ee holds the client-side key handling for end-to-end encrypted volumes
// (docs/design-e2ee.md): one password becomes separate keys for login and for the volume,
// the client writes gocryptfs.conf itself, and the recovery code is the master key.
package e2ee

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
)

// Argon2id cost for the root key. Fixed for version 1 so every client derives the same
// keys; a later version gets a new label and a new salt prefix.
const (
	rootTime      uint32 = 3
	rootMemoryKiB uint32 = 64 * 1024
	rootThreads   uint8  = 4
)

// Keys derived from the account password. The server must only ever see AuthKey.
type Keys struct {
	// AuthKey is sent instead of the password; the server stores a verifier of it.
	AuthKey string
	// VolumePassphrase unlocks gocryptfs.conf. It never leaves the client.
	VolumePassphrase []byte
}

// The "secdisk/..." labels here and elsewhere (stick, escrow, recovery, the web UI's derive.js) are
// fixed protocol constants from the product's earlier name: changing one would change every key
// derived from it and lock users out of their storage.

// salt binds the root key to the user. It needs no server round trip, so login does not
// reveal whether a user exists. The cost of Argon2id, not the salt, is what slows guessing.
func salt(username string) []byte {
	h := sha256.Sum256([]byte("secdisk/kdf/v1\x00" + strings.ToLower(strings.TrimSpace(username))))
	return h[:]
}

// Derive turns the password into the login key and the volume passphrase. Both come from
// one slow Argon2id run and are separated by HKDF labels, so knowing AuthKey does not help
// to find VolumePassphrase.
func Derive(username, password string) (*Keys, error) {
	if username == "" || password == "" {
		return nil, errors.New("username and password are required")
	}
	root := argon2.IDKey([]byte(password), salt(username), rootTime, rootMemoryKiB, rootThreads, 32)
	defer wipe(root)
	auth, err := expand(root, "secdisk/auth/v1")
	if err != nil {
		return nil, err
	}
	vol, err := expand(root, "secdisk/volume/v1")
	if err != nil {
		return nil, err
	}
	defer wipe(auth)
	defer wipe(vol)
	return &Keys{
		AuthKey:          hex.EncodeToString(auth),
		VolumePassphrase: []byte(hex.EncodeToString(vol)),
	}, nil
}

func expand(root []byte, label string) ([]byte, error) {
	out := make([]byte, 32)
	if _, err := io.ReadFull(hkdf.New(sha256.New, root, nil, []byte(label)), out); err != nil {
		return nil, err
	}
	return out, nil
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
