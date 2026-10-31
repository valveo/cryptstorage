package e2ee

import (
	"bytes"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"errors"
	"strings"
)

// The recovery code is the master key plus a 4-byte checksum, in base32 groups:
//
//	XXXXXX-XXXXXX-... (58 characters in groups of 6, last group shorter)
//
// The checksum catches typing mistakes before anything is written. It is NOT a check that the key
// opens the volume (gocryptfs cannot tell, see design-e2ee.md F6): the caller must read the canary file.
var enc32 = base32.StdEncoding.WithPadding(base32.NoPadding)

func checksum(key []byte) []byte {
	h := sha256.Sum256(append([]byte("secdisk/recovery/v1\x00"), key...))
	return h[:4]
}

// RecoveryCode formats masterKey for the user to write down.
func RecoveryCode(masterKey []byte) (string, error) {
	if len(masterKey) != 32 {
		return "", errors.New("master key must be 32 bytes")
	}
	s := enc32.EncodeToString(append(append([]byte{}, masterKey...), checksum(masterKey)...))
	var parts []string
	for len(s) > 6 {
		parts = append(parts, s[:6])
		s = s[6:]
	}
	return strings.Join(append(parts, s), "-"), nil
}

// ParseRecoveryCode accepts upper or lower case, spaces and dashes.
func ParseRecoveryCode(code string) ([]byte, error) {
	clean := strings.ToUpper(strings.NewReplacer("-", "", " ", "", "\n", "", "\t", "").Replace(code))
	raw, err := enc32.DecodeString(clean)
	if err != nil || len(raw) != 36 {
		return nil, errors.New("this is not a valid recovery code")
	}
	key, sum := raw[:32], raw[32:]
	if !bytes.Equal(sum, checksum(key)) {
		return nil, errors.New("the recovery code has a typing mistake")
	}
	return key, nil
}

// RecoveryProof is what the client sends to the server to prove it holds the recovery code,
// without revealing the master key: a one-way HKDF output the server stores only as a slow hash.
func RecoveryProof(masterKey []byte) (string, error) {
	out, err := expand(masterKey, "secdisk/recover-auth/v1")
	if err != nil {
		return "", err
	}
	defer wipe(out)
	return hex.EncodeToString(out), nil
}
