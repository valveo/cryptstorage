package e2ee

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"

	"golang.org/x/crypto/hkdf"
)

// Escrow: the master key sealed to an organisation's X25519 public key, so the operator (and only
// the holder of the private key) can recover a user's data. The server stores the blob but cannot open it.
//
//	blob = ephemeralPublic(32) | nonce(12) | AES-256-GCM(key, masterKey, aad = ephemeralPublic | recipientPublic) | tag(16)
//	key  = HKDF-SHA256(X25519 shared secret, salt = ephemeralPublic | recipientPublic, info "secdisk/escrow/v1")
//
// 184 hex characters. scripts/escrow.py opens it.
const escrowInfo = "secdisk/escrow/v1"

func escrowKey(shared, eph, recipient []byte) (cipher.AEAD, error) {
	k := make([]byte, 32)
	defer wipe(k)
	if _, err := io.ReadFull(hkdf.New(sha256.New, shared, append(append([]byte{}, eph...), recipient...), []byte(escrowInfo)), k); err != nil {
		return nil, err
	}
	b, err := aes.NewCipher(k)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(b)
}

// SealToEscrow returns the hex blob to upload.
func SealToEscrow(masterKey []byte, recipientPublicHex string) (string, error) {
	rb, err := hex.DecodeString(recipientPublicHex)
	if err != nil || len(rb) != 32 {
		return "", errors.New("escrow public key must be 32 bytes of hex")
	}
	recipient, err := ecdh.X25519().NewPublicKey(rb)
	if err != nil {
		return "", err
	}
	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	shared, err := eph.ECDH(recipient)
	if err != nil {
		return "", err
	}
	defer wipe(shared)
	ephPub := eph.PublicKey().Bytes()
	aead, err := escrowKey(shared, ephPub, rb)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	aad := append(append([]byte{}, ephPub...), rb...)
	out := append(append([]byte{}, ephPub...), nonce...)
	out = aead.Seal(out, nonce, masterKey, aad)
	return hex.EncodeToString(out), nil
}

// OpenEscrow is the operator's side (also implemented in scripts/escrow.py).
func OpenEscrow(blobHex, privateHex string) ([]byte, error) {
	blob, err := hex.DecodeString(blobHex)
	if err != nil || len(blob) != 92 {
		return nil, errors.New("bad escrow blob")
	}
	pb, err := hex.DecodeString(privateHex)
	if err != nil {
		return nil, err
	}
	priv, err := ecdh.X25519().NewPrivateKey(pb)
	if err != nil {
		return nil, err
	}
	eph, err := ecdh.X25519().NewPublicKey(blob[:32])
	if err != nil {
		return nil, err
	}
	shared, err := priv.ECDH(eph)
	if err != nil {
		return nil, err
	}
	defer wipe(shared)
	rb := priv.PublicKey().Bytes()
	aead, err := escrowKey(shared, blob[:32], rb)
	if err != nil {
		return nil, err
	}
	aad := append(append([]byte{}, blob[:32]...), rb...)
	return aead.Open(nil, blob[32:44], blob[44:], aad)
}
