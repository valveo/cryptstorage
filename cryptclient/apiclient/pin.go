package apiclient

import (
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
)

// A pin is one trusted identity of the server. Two forms are accepted:
//
//	sha256/<base64>   SHA-256 of a certificate's public key (SPKI), as in HPKP / curl --pinnedpubkey.
//	<64 hex chars>    SHA-256 fingerprint of the leaf certificate (the older form).
//
// Several pins can be given, separated by commas or whitespace; one match is enough.
//
// Prefer SPKI pins. A leaf fingerprint changes at every certificate renewal (Let's
// Encrypt: every ~60-90 days), an SPKI pin only when the key changes. With certbot's
// --reuse-key the key stays the same across renewals. SPKI pins also match
// intermediate and root certificates in the verified chain, so a second pin (a
// backup) can be the CA's intermediate: the client keeps working if you rotate the
// key, as long as the new certificate comes from the same CA.
type pin struct {
	spki bool
	sum  [32]byte
}

// SPKIPin returns the pin string ("sha256/...") for a certificate's public key.
func SPKIPin(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return "sha256/" + base64.StdEncoding.EncodeToString(sum[:])
}

func parsePins(spec string) ([]pin, error) {
	var pins []pin
	for _, field := range strings.FieldsFunc(spec, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' || r == '\n' }) {
		field = strings.TrimSpace(field)
		var p pin
		switch {
		case strings.HasPrefix(field, "sha256/"):
			raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(field, "sha256/"))
			if err != nil || len(raw) != sha256.Size {
				return nil, fmt.Errorf("invalid pin %q: expected sha256/<base64 of 32 bytes>", field)
			}
			p.spki = true
			copy(p.sum[:], raw)
		default:
			hexStr := strings.ToLower(strings.ReplaceAll(field, ":", ""))
			raw, err := hex.DecodeString(hexStr)
			if err != nil || len(raw) != sha256.Size {
				return nil, fmt.Errorf("invalid pin %q: expected sha256/<base64> or a 64-character hex fingerprint", field)
			}
			copy(p.sum[:], raw)
		}
		pins = append(pins, p)
	}
	return pins, nil
}

// verifyPins runs after the normal certificate verification (it never replaces it).
// It succeeds if any pin matches: an SPKI pin against any certificate of the verified
// chain, a fingerprint pin against the leaf.
func verifyPins(cs tls.ConnectionState, pins []pin) error {
	if len(cs.PeerCertificates) == 0 {
		return fmt.Errorf("no peer certificates in TLS handshake")
	}
	chain := cs.PeerCertificates
	if len(cs.VerifiedChains) > 0 {
		chain = cs.VerifiedChains[0]
	}

	for _, p := range pins {
		if p.spki {
			for _, cert := range chain {
				sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
				if subtle.ConstantTimeCompare(sum[:], p.sum[:]) == 1 {
					return nil
				}
			}
			continue
		}
		sum := sha256.Sum256(cs.PeerCertificates[0].Raw)
		if subtle.ConstantTimeCompare(sum[:], p.sum[:]) == 1 {
			return nil
		}
	}

	return fmt.Errorf(
		"TLS certificate does not match any pin\n"+
			"  Server key pin: %s\n"+
			"  This may indicate a man-in-the-middle attack. If you changed the server's key,\n"+
			"  update CRYPTSTORAGE_CERT_PIN (several pins may be given, separated by commas).",
		SPKIPin(cs.PeerCertificates[0]),
	)
}
