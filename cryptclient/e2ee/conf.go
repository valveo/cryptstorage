package e2ee

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/scrypt"
)

// gocryptfs.conf (format 2.x, verified against gocryptfs 2.4.0):
//
//	wrapKey      = HKDF-SHA256(scrypt(passphrase, salt, N, r, p), info "AES-GCM file content encryption")
//	EncryptedKey = nonce(16) | AES-256-GCM(wrapKey, 128-bit nonce, masterKey, aad = 8 zero bytes)
//
// Writing it ourselves lets the client choose the master key (and show the recovery code)
// without driving gocryptfs through a pseudo-terminal.
const (
	hkdfInfo  = "AES-GCM file content encryption"
	confNonce = 16

	// Limits when READING a config from the server: it may be hostile and must not make
	// the client allocate gigabytes. 2^22 * 128 * r bytes is about 512 MiB at the limit.
	maxScryptNPow = 22
	minScryptNPow = 10
	// Default cost for new volumes: about 2^16 is gocryptfs's own default.
	DefaultScryptNPow = 16
)

var featureFlags = []string{"HKDF", "GCMIV128", "DirIV", "EMENames", "LongNames", "Raw64"}

type scryptObject struct {
	Salt   string `json:"Salt"`
	N      int    `json:"N"`
	R      int    `json:"R"`
	P      int    `json:"P"`
	KeyLen int    `json:"KeyLen"`
}

type confFile struct {
	Creator      string       `json:"Creator"`
	EncryptedKey string       `json:"EncryptedKey"`
	ScryptObject scryptObject `json:"ScryptObject"`
	Version      int          `json:"Version"`
	FeatureFlags []string     `json:"FeatureFlags"`
}

func wrapKey(passphrase, salt []byte, n, r, p int) (cipher.AEAD, error) {
	h, err := scrypt.Key(passphrase, salt, n, r, p, 32)
	if err != nil {
		return nil, err
	}
	defer wipe(h)
	key := make([]byte, 32)
	defer wipe(key)
	if _, err := io.ReadFull(hkdf.New(sha256.New, h, nil, []byte(hkdfInfo)), key); err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCMWithNonceSize(block, confNonce)
}

// NewMasterKey returns 32 random bytes.
func NewMasterKey() ([]byte, error) {
	k := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, k); err != nil {
		return nil, err
	}
	return k, nil
}

// MakeConf wraps masterKey under passphrase and returns the text of gocryptfs.conf.
func MakeConf(masterKey, passphrase []byte, nPow int) ([]byte, error) {
	if len(masterKey) != 32 {
		return nil, errors.New("master key must be 32 bytes")
	}
	if nPow < minScryptNPow || nPow > maxScryptNPow {
		return nil, fmt.Errorf("scrypt cost 2^%d is out of range", nPow)
	}
	salt := make([]byte, 32)
	nonce := make([]byte, confNonce)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	aead, err := wrapKey(passphrase, salt, 1<<nPow, 8, 1)
	if err != nil {
		return nil, err
	}
	enc := aead.Seal(append([]byte{}, nonce...), nonce, masterKey, make([]byte, 8))
	b64 := base64.StdEncoding.EncodeToString
	return json.MarshalIndent(confFile{
		Creator:      "CryptStorage",
		EncryptedKey: b64(enc),
		ScryptObject: scryptObject{Salt: b64(salt), N: 1 << nPow, R: 8, P: 1, KeyLen: 32},
		Version:      2,
		FeatureFlags: featureFlags,
	}, "", "\t")
}

// ErrWrongPassphrase is returned when the master key cannot be unwrapped.
var ErrWrongPassphrase = errors.New("wrong passphrase or damaged gocryptfs.conf")

// ReadMasterKey unwraps the master key from the text of gocryptfs.conf.
func ReadMasterKey(conf, passphrase []byte) ([]byte, error) {
	var c confFile
	if err := json.Unmarshal(conf, &c); err != nil {
		return nil, fmt.Errorf("gocryptfs.conf: %w", err)
	}
	s := c.ScryptObject
	if c.Version != 2 || s.KeyLen != 32 || s.R != 8 || s.P != 1 ||
		s.N < 1<<minScryptNPow || s.N > 1<<maxScryptNPow || s.N&(s.N-1) != 0 {
		return nil, errors.New("gocryptfs.conf: unsupported or unsafe parameters")
	}
	salt, err := base64.StdEncoding.DecodeString(s.Salt)
	if err != nil || len(salt) < 16 {
		return nil, errors.New("gocryptfs.conf: bad salt")
	}
	enc, err := base64.StdEncoding.DecodeString(c.EncryptedKey)
	if err != nil || len(enc) < confNonce+16 {
		return nil, errors.New("gocryptfs.conf: bad EncryptedKey")
	}
	aead, err := wrapKey(passphrase, salt, s.N, s.R, s.P)
	if err != nil {
		return nil, err
	}
	key, err := aead.Open(nil, enc[:confNonce], enc[confNonce:], make([]byte, 8))
	if err != nil {
		return nil, ErrWrongPassphrase
	}
	return key, nil
}
