package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/pbkdf2"
)

var secret = []byte("-----BEGIN OPENSSH PRIVATE KEY-----\nsecret key material\n-----END OPENSSH PRIVATE KEY-----\n")

// legacyEncrypt reproduces the old v1 writer exactly, to prove old sticks keep working.
func legacyEncrypt(t *testing.T, plaintext []byte, password string) []byte {
	t.Helper()
	salt, nonce := make([]byte, saltLen), make([]byte, nonceLen)
	io.ReadFull(rand.Reader, salt)
	io.ReadFull(rand.Reader, nonce)
	block, _ := aes.NewCipher(pbkdf2.Key([]byte(password), salt, 200_000, 32, sha256.New))
	gcm, _ := cipher.NewGCM(block)
	return append(append(salt, nonce...), gcm.Seal(nil, nonce, plaintext, nil)...)
}

func TestRoundTrip(t *testing.T) {
	blob, err := EncryptKey(secret, "correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(blob, []byte("CSK2")) {
		t.Fatal("new keys must use the v2 format")
	}
	got, err := DecryptKey(blob, "correct horse battery")
	if err != nil || !bytes.Equal(got, secret) {
		t.Fatalf("round trip failed: %v", err)
	}
	if _, err := DecryptKey(blob, "wrong password"); err == nil || !strings.Contains(err.Error(), "wrong password") {
		t.Fatalf("wrong password must be rejected, got %v", err)
	}
	if NeedsUpgrade(blob) {
		t.Fatal("a fresh v2 blob must not need an upgrade")
	}
}

func TestEveryBlobIsDifferent(t *testing.T) {
	a, _ := EncryptKey(secret, "pw")
	b, _ := EncryptKey(secret, "pw")
	if bytes.Equal(a, b) {
		t.Fatal("salt and nonce must be random")
	}
}

func TestParametersAreAuthenticated(t *testing.T) {
	blob, _ := EncryptKey(secret, "pw")

	for _, tc := range []struct {
		name   string
		mutate func(b []byte)
	}{
		{"time", func(b []byte) { binary.BigEndian.PutUint32(b[4:], 2) }},      // weaker cost
		{"memory", func(b []byte) { binary.BigEndian.PutUint32(b[8:], 8192) }}, // weaker cost
		{"threads", func(b []byte) { b[12] = 2 }},
		{"salt", func(b []byte) { b[headerSize] ^= 1 }},
		{"ciphertext", func(b []byte) { b[len(b)-1] ^= 1 }},
	} {
		tampered := append([]byte(nil), blob...)
		tc.mutate(tampered)
		if _, err := DecryptKey(tampered, "pw"); err == nil {
			t.Fatalf("tampering with %s was not detected", tc.name)
		}
	}
}

func TestLegacyKeysStillDecryptAndAskForAnUpgrade(t *testing.T) {
	old := legacyEncrypt(t, secret, "old password")
	got, err := DecryptKey(old, "old password")
	if err != nil || !bytes.Equal(got, secret) {
		t.Fatalf("legacy blob no longer readable: %v", err)
	}
	if _, err := DecryptKey(old, "nope"); err == nil {
		t.Fatal("wrong password accepted on legacy blob")
	}
	if !NeedsUpgrade(old) {
		t.Fatal("legacy blob must report that it needs an upgrade")
	}

	// the upgrade path: decrypt, re-encrypt, same secret
	upgraded, _ := EncryptKey(got, "old password")
	again, err := DecryptKey(upgraded, "old password")
	if err != nil || !bytes.Equal(again, secret) || NeedsUpgrade(upgraded) {
		t.Fatalf("upgrade did not produce a clean v2 blob: %v", err)
	}
}

func TestWeakerParametersAreReportedAsNeedingUpgrade(t *testing.T) {
	saved := currentParams
	defer func() { currentParams = saved }()
	currentParams = argonParams{1, 8 * 1024, 1}
	weak, _ := EncryptKey(secret, "pw")
	currentParams = saved
	if got, err := DecryptKey(weak, "pw"); err != nil || !bytes.Equal(got, secret) {
		t.Fatalf("a key written with weaker parameters must still open: %v", err)
	}
	if !NeedsUpgrade(weak) {
		t.Fatal("weaker parameters should be flagged")
	}
}

// The blob comes from a removable stick: absurd parameters must be refused cheaply.
func TestCraftedParametersCannotExhaustMemory(t *testing.T) {
	blob, _ := EncryptKey(secret, "pw")
	for _, mem := range []uint32{0xFFFFFFFF, 4 * 1024 * 1024, 0} {
		bad := append([]byte(nil), blob...)
		binary.BigEndian.PutUint32(bad[8:], mem)
		start := time.Now()
		if _, err := DecryptKey(bad, "pw"); err == nil {
			t.Fatalf("memory=%d accepted", mem)
		}
		if time.Since(start) > 2*time.Second {
			t.Fatalf("memory=%d took %v: parameters were not bounded before deriving", mem, time.Since(start))
		}
	}
	bad := append([]byte(nil), blob...)
	binary.BigEndian.PutUint32(bad[4:], 0xFFFFFFFF)
	start := time.Now()
	if _, err := DecryptKey(bad, "pw"); err == nil || time.Since(start) > 2*time.Second {
		t.Fatalf("huge time cost not bounded (err=%v, %v)", err, time.Since(start))
	}
}

func TestShortAndEmptyBlobs(t *testing.T) {
	for _, b := range [][]byte{nil, {}, []byte("CSK2"), make([]byte, 10)} {
		if _, err := DecryptKey(b, "pw"); err == nil {
			t.Fatalf("blob of %d bytes accepted", len(b))
		}
	}
}
