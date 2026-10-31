package crypto

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

// v3, sealed: the key needs the password AND the stick secret the server holds.
//
//	"CSK3" | time uint32 BE | memory KiB uint32 BE | threads uint8 | stick id(16) | salt(32) | nonce(12) | ciphertext+tag
//
// K = HKDF-SHA256(Argon2id(password, salt) || stick secret, info "secdisk/stick/v3"). The header with
// the stick id is the AES-GCM additional data. The server releases the secret only after the full login
// (password and second factor), so a found or copied stick cannot be attacked offline: every password
// guess has to go through the server's throttled login.
const (
	magicV3      = "CSK3"
	stickIDLen   = 16
	headerSizeV3 = headerSize + stickIDLen
	secretLen    = 32
)

// ErrSealed means the key needs the stick secret from the server (DecryptSealed).
var ErrSealed = errors.New("the key on the stick needs the server's stick secret")

// StickID returns the id of a sealed key, or false for the older password-only formats.
func StickID(blob []byte) ([stickIDLen]byte, bool) {
	var id [stickIDLen]byte
	if _, ok := parseHeaderV3(blob); !ok {
		return id, false
	}
	copy(id[:], blob[headerSize:headerSizeV3])
	return id, true
}

func parseHeaderV3(blob []byte) (argonParams, bool) {
	if len(blob) < headerSizeV3+saltLen+nonceLen+1 || !bytes.HasPrefix(blob, []byte(magicV3)) {
		return argonParams{}, false
	}
	p := argonParams{ // the same parameter layout as v2
		time:      binary.BigEndian.Uint32(blob[4:]),
		memoryKiB: binary.BigEndian.Uint32(blob[8:]),
		threads:   blob[12],
	}
	return p, p.valid()
}

// EncryptSealed encrypts a plaintext key with the password and the stick secret (v3).
func EncryptSealed(plaintext []byte, password string, stickID [stickIDLen]byte, secret []byte) ([]byte, error) {
	if len(secret) != secretLen {
		return nil, fmt.Errorf("stick secret must be %d bytes", secretLen)
	}
	salt := make([]byte, saltLen)
	nonce := make([]byte, nonceLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	header := append([]byte(magicV3), currentParams.header()[len(magicV2):]...)
	header = append(header, stickID[:]...)
	k, err := sealedKey(password, salt, currentParams, secret)
	if err != nil {
		return nil, err
	}
	gcm, err := newGCM(k)
	if err != nil {
		return nil, err
	}
	out := append(header, salt...)
	out = append(out, nonce...)
	return append(out, gcm.Seal(nil, nonce, plaintext, header)...), nil
}

// DecryptSealed opens a v3 key with the password and the stick secret.
func DecryptSealed(blob []byte, password string, secret []byte) ([]byte, error) {
	params, ok := parseHeaderV3(blob)
	if !ok {
		return nil, errors.New("not a sealed key")
	}
	rest := blob[headerSizeV3:]
	salt, nonce, ciphertext := rest[:saltLen], rest[saltLen:saltLen+nonceLen], rest[saltLen+nonceLen:]
	k, err := sealedKey(password, salt, params, secret)
	if err != nil {
		return nil, err
	}
	gcm, err := newGCM(k)
	if err != nil {
		return nil, err
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, blob[:headerSizeV3])
	if err != nil {
		return nil, fmt.Errorf("decryption failed: wrong password, a replaced stick secret, or a corrupted key")
	}
	return plaintext, nil
}

func sealedKey(password string, salt []byte, p argonParams, secret []byte) ([]byte, error) {
	if len(secret) != secretLen {
		return nil, fmt.Errorf("stick secret must be %d bytes", secretLen)
	}
	ikm := append(deriveArgon(password, salt, p), secret...)
	defer wipeBytes(ikm)
	k := make([]byte, keyLen)
	if _, err := io.ReadFull(hkdf.New(sha256.New, ikm, nil, []byte("secdisk/stick/v3")), k); err != nil {
		return nil, err
	}
	return k, nil
}

func wipeBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
