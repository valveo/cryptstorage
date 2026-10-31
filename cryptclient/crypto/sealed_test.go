package crypto

import (
	"bytes"
	"crypto/rand"
	"errors"
	"testing"
)

func TestSealedRoundTrip(t *testing.T) {
	pem := []byte("-----BEGIN OPENSSH PRIVATE KEY-----\ntest\n-----END OPENSSH PRIVATE KEY-----\n")
	var id [16]byte
	rand.Read(id[:])
	secret := make([]byte, 32)
	rand.Read(secret)

	blob, err := EncryptSealed(pem, "correct horse battery", id, secret)
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := StickID(blob); !ok || got != id {
		t.Fatalf("stick id %x %v", got, ok)
	}
	if NeedsUpgrade(blob) {
		t.Error("a fresh sealed key needs no upgrade")
	}
	out, err := DecryptSealed(blob, "correct horse battery", secret)
	if err != nil || !bytes.Equal(out, pem) {
		t.Fatalf("decrypt: %v", err)
	}

	// the password alone does not open it: that is the point
	if _, err := DecryptKey(blob, "correct horse battery"); !errors.Is(err, ErrSealed) {
		t.Fatalf("DecryptKey on a sealed key: %v", err)
	}
	other := make([]byte, 32)
	rand.Read(other)
	if _, err := DecryptSealed(blob, "correct horse battery", other); err == nil {
		t.Fatal("opened with another stick secret")
	}
	if _, err := DecryptSealed(blob, "wrong password here!", secret); err == nil {
		t.Fatal("opened with a wrong password")
	}
	// the stick id is bound to the ciphertext: moving the key to another id breaks it
	moved := append([]byte(nil), blob...)
	moved[headerSize] ^= 1
	if _, err := DecryptSealed(moved, "correct horse battery", secret); err == nil {
		t.Fatal("opened with a changed stick id")
	}
}

func TestOldFormatsHaveNoStickID(t *testing.T) {
	blob, err := EncryptKey([]byte("pem"), "password")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := StickID(blob); ok {
		t.Fatal("a v2 key reported a stick id")
	}
}
