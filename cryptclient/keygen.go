package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"golang.org/x/crypto/ssh"
)

// generateSSHKeyPair generates an ECDSA P-256 SSH key pair.
// Returns (publicKeyAuthorizedKeysFormat, privateKeyPEM, error).
func generateSSHKeyPair() ([]byte, []byte, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generating key: %w", err)
	}

	// Encode private key to PEM
	privDER, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("marshaling private key: %w", err)
	}

	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privDER,
	})

	// Encode public key in SSH authorized_keys format
	pubKey, err := ssh.NewPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("creating SSH public key: %w", err)
	}

	authorizedKey := ssh.MarshalAuthorizedKey(pubKey)
	return authorizedKey, privPEM, nil
}
