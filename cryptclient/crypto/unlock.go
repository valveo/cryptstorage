package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/pbkdf2"
)

// Three on-disk formats exist; v3, sealed with the server's stick secret, is in sealed.go.
//
// v2 (written by EncryptKey):
//
//	"CSK2" | time uint32 BE | memory KiB uint32 BE | threads uint8 | salt(32) | nonce(12) | ciphertext+tag
//
// The key is derived with Argon2id. The 13-byte header (magic and parameters) is bound
// to the ciphertext as AES-GCM additional data, so the parameters cannot be changed
// without detection, and later versions can raise the cost without breaking old keys.
//
// v1 (legacy, still readable):
//
//	salt(32) | nonce(12) | ciphertext+tag     with PBKDF2-HMAC-SHA256, 200,000 iterations
//
// Whoever finds a lost USB stick can try passwords offline at the speed their hardware
// allows, so the derivation should be memory-hard: Argon2id makes GPU and ASIC guessing
// far more expensive than PBKDF2 does.
const (
	saltLen  = 32
	nonceLen = 12
	keyLen   = 32 // AES-256

	legacyIterations = 200_000

	magicV2    = "CSK2"
	headerSize = len(magicV2) + 4 + 4 + 1

	// Parameters for new keys: 3 passes over 64 MiB, 4 lanes (a few hundred milliseconds)
	argonTime      uint32 = 3
	argonMemoryKiB uint32 = 64 * 1024
	argonThreads   uint8  = 4

	// Upper limits accepted when READING a key: the blob comes from a stick that may
	// have been tampered with, and must not be able to make the client allocate gigabytes.
	maxArgonTime      = 10
	maxArgonMemoryKiB = 512 * 1024
	maxArgonThreads   = 16
)

type argonParams struct {
	time      uint32
	memoryKiB uint32
	threads   uint8
}

var currentParams = argonParams{argonTime, argonMemoryKiB, argonThreads}

func (p argonParams) valid() bool {
	return p.time >= 1 && p.time <= maxArgonTime &&
		p.memoryKiB >= 8*uint32(p.threads) && p.memoryKiB <= maxArgonMemoryKiB &&
		p.threads >= 1 && p.threads <= maxArgonThreads
}

func (p argonParams) header() []byte {
	h := make([]byte, headerSize)
	copy(h, magicV2)
	binary.BigEndian.PutUint32(h[4:], p.time)
	binary.BigEndian.PutUint32(h[8:], p.memoryKiB)
	h[12] = p.threads
	return h
}

func parseHeader(blob []byte) (argonParams, bool) {
	if len(blob) < headerSize+saltLen+nonceLen+1 || !bytes.HasPrefix(blob, []byte(magicV2)) {
		return argonParams{}, false
	}
	p := argonParams{
		time:      binary.BigEndian.Uint32(blob[4:]),
		memoryKiB: binary.BigEndian.Uint32(blob[8:]),
		threads:   blob[12],
	}
	return p, p.valid()
}

// EncryptKey encrypts a plaintext key (e.g. PEM bytes) with a password using the v2 format.
func EncryptKey(plaintext []byte, password string) ([]byte, error) {
	salt := make([]byte, saltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("generating salt: %w", err)
	}
	nonce := make([]byte, nonceLen)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generating nonce: %w", err)
	}

	header := currentParams.header()
	gcm, err := newGCM(deriveArgon(password, salt, currentParams))
	if err != nil {
		return nil, err
	}
	ciphertext := gcm.Seal(nil, nonce, plaintext, header)

	out := make([]byte, 0, headerSize+saltLen+nonceLen+len(ciphertext))
	out = append(out, header...)
	out = append(out, salt...)
	out = append(out, nonce...)
	out = append(out, ciphertext...)
	return out, nil
}

// DecryptKey decrypts a blob produced by EncryptKey (either format) using the password.
// Returns the original plaintext or an error if the password is wrong.
func DecryptKey(blob []byte, password string) ([]byte, error) {
	if _, ok := StickID(blob); ok {
		return nil, ErrSealed
	}
	if params, ok := parseHeader(blob); ok {
		rest := blob[headerSize:]
		salt, nonce, ciphertext := rest[:saltLen], rest[saltLen:saltLen+nonceLen], rest[saltLen+nonceLen:]
		gcm, err := newGCM(deriveArgon(password, salt, params))
		if err != nil {
			return nil, err
		}
		plaintext, err := gcm.Open(nil, nonce, ciphertext, blob[:headerSize])
		if err != nil {
			return nil, fmt.Errorf("decryption failed: wrong password or corrupted key")
		}
		return plaintext, nil
	}

	// v1 (a v2 header with out-of-range parameters is treated as v1 data and fails below)
	if len(blob) < saltLen+nonceLen+1 {
		return nil, fmt.Errorf("blob too short")
	}
	salt, nonce, ciphertext := blob[:saltLen], blob[saltLen:saltLen+nonceLen], blob[saltLen+nonceLen:]
	gcm, err := newGCM(pbkdf2.Key([]byte(password), salt, legacyIterations, keyLen, sha256.New))
	if err != nil {
		return nil, err
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: wrong password or corrupted key")
	}
	return plaintext, nil
}

// NeedsUpgrade reports whether the blob uses the legacy format or weaker parameters
// than EncryptKey uses today.
func NeedsUpgrade(blob []byte) bool {
	p, ok := parseHeader(blob)
	if v3, sealed := parseHeaderV3(blob); sealed {
		p, ok = v3, true
	}
	if !ok {
		return true
	}
	return p.time < currentParams.time || p.memoryKiB < currentParams.memoryKiB || p.threads < currentParams.threads
}

func deriveArgon(password string, salt []byte, p argonParams) []byte {
	return argon2.IDKey([]byte(password), salt, p.time, p.memoryKiB, p.threads, keyLen)
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
