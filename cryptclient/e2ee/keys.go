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
// derived from it and lock users out of their storage. "cryptstorage/kdf/v2" (saltV2) is frozen the same way.

// salt (version 1) binds the root key to the user. It needs no server round trip, so login does not
// reveal whether a user exists. The cost of Argon2id, not the salt, is what slows guessing.
func salt(username string) []byte {
	h := sha256.Sum256([]byte("secdisk/kdf/v1\x00" + strings.ToLower(strings.TrimSpace(username))))
	return h[:]
}

// saltV2 adds this server's random kdf_salt (32 bytes, public in /server-info), so nothing can be
// computed for a username before the server exists, and the same username differs between servers.
// The server part has a fixed length, so the concatenation is unambiguous.
func saltV2(serverSalt []byte, username string) []byte {
	h := sha256.New()
	h.Write([]byte("cryptstorage/kdf/v2\x00"))
	h.Write(serverSalt)
	h.Write([]byte(strings.ToLower(strings.TrimSpace(username))))
	return h.Sum(nil)
}

// Derive turns the password into the login key and the volume passphrase with the version 1 salt
// (username only), as v0.1.0 did. New keys use DeriveSet. Both keys come from one slow Argon2id run
// and are separated by HKDF labels, so knowing AuthKey does not help to find VolumePassphrase.
func Derive(username, password string) (*Keys, error) {
	return derive(salt(username), username, password)
}

// DeriveV2 is Derive with the version 2 salt: serverSalt is the server's kdf_salt (32 bytes).
func DeriveV2(serverSalt []byte, username, password string) (*Keys, error) {
	if len(serverSalt) != 32 {
		return nil, errors.New("the server's key derivation salt must be 32 bytes")
	}
	return derive(saltV2(serverSalt, username), username, password)
}

func derive(salt []byte, username, password string) (*Keys, error) {
	if username == "" || password == "" {
		return nil, errors.New("username and password are required")
	}
	root := argon2.IDKey([]byte(password), salt, rootTime, rootMemoryKiB, rootThreads, 32)
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

// KeySet is what one password gives on a given server: the keys for the current key derivation and,
// while accounts move over from version 1, the version 1 keys too (docs/design-e2ee.md, section 5a).
type KeySet struct {
	// Current: version 2 when the server publishes a kdf_salt, else version 1.
	Current *Keys
	// Legacy: the version 1 keys when Current is version 2; nil otherwise.
	Legacy *Keys
	// Version of Current.
	Version int
}

// DeriveSet derives the keys for a server whose /server-info gave kdfSaltHex ("" from older
// servers). Two Argon2id runs while the server has a salt: the account may still be on version 1.
func DeriveSet(kdfSaltHex, username, password string) (*KeySet, error) {
	v1, err := Derive(username, password)
	if err != nil {
		return nil, err
	}
	if kdfSaltHex == "" {
		return &KeySet{Current: v1, Version: 1}, nil
	}
	serverSalt, err := hex.DecodeString(kdfSaltHex)
	if err != nil || len(serverSalt) != 32 {
		return nil, errors.New("the server sent a malformed key derivation salt")
	}
	v2, err := DeriveV2(serverSalt, username, password)
	if err != nil {
		return nil, err
	}
	return &KeySet{Current: v2, Legacy: v1, Version: 2}, nil
}

// For returns the keys of an account whose login key is the given version.
func (s *KeySet) For(version int) *Keys {
	if version < s.Version && s.Legacy != nil {
		return s.Legacy
	}
	return s.Current
}

// LegacyAuthKey is the version 1 login key to send next to the current one, or "".
func (s *KeySet) LegacyAuthKey() string {
	if s.Legacy == nil {
		return ""
	}
	return s.Legacy.AuthKey
}

// Passphrases lists the volume passphrases to try, current first.
func (s *KeySet) Passphrases() [][]byte {
	if s.Legacy == nil {
		return [][]byte{s.Current.VolumePassphrase}
	}
	return [][]byte{s.Current.VolumePassphrase, s.Legacy.VolumePassphrase}
}
