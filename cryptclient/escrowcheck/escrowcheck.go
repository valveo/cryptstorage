// Package escrowcheck remembers, on the stick, the escrow settings the user last accepted, and
// tells when the server's differ (docs/design-e2ee.md section 14, "Escrow").
//
// The operator controls the server and its web UI, so they can change what both say. The client
// is the one place the operator does not control: this record is the user's protection against a
// quiet change, and the client never seals the master key again on its own because of one.
package escrowcheck

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"cryptclient/apiclient"
)

// File is the record's name on the stick's data partition, next to the TLS pin and host keys.
const File = "cryptstorage.escrow"

// Record is what the user accepted. KeyFingerprint is empty when escrow is off.
type Record struct {
	Policy         string `json:"recovery_policy"`
	KeyFingerprint string `json:"escrow_key_fingerprint,omitempty"`
}

// Fingerprint is SHA-256 of the raw X25519 public key, hex (the server computes the same value).
func Fingerprint(publicHex string) (string, error) {
	raw, err := hex.DecodeString(publicHex)
	if err != nil || len(raw) != 32 {
		return "", errors.New("escrow public key must be 32 bytes of hex")
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

// Short is the fingerprint as people compare it: the first 32 characters in groups of four.
func Short(fp string) string {
	if fp == "" {
		return "-"
	}
	if len(fp) > 32 {
		fp = fp[:32]
	}
	out := ""
	for i := 0; i < len(fp); i += 4 {
		if i > 0 {
			out += " "
		}
		out += fp[i:min(i+4, len(fp))]
	}
	return out
}

// FromServer computes the record for what the server says now. The fingerprint is computed here
// from the key itself, not taken from the server's escrow_key_fingerprint.
func FromServer(info *apiclient.ServerInfo) (Record, error) {
	r := Record{Policy: info.RecoveryPolicy}
	if r.Policy == "user" {
		return r, nil
	}
	if info.EscrowPublicKey == nil {
		return r, errors.New("the server has escrow on but gives no escrow key")
	}
	fp, err := Fingerprint(*info.EscrowPublicKey)
	if err != nil {
		return r, err
	}
	r.KeyFingerprint = fp
	return r, nil
}

// On tells whether this record's policy seals a copy for the organisation.
func (r Record) On() bool { return r.Policy == "escrow" || r.Policy == "both" }

// Describe is one line for status output and warnings.
func (r Record) Describe() string {
	if !r.On() {
		return fmt.Sprintf("off (policy %q)", r.Policy)
	}
	return fmt.Sprintf("ON (policy %q, organisation key %s)", r.Policy, Short(r.KeyFingerprint))
}

// Load reads the record from the stick. found is false when there is none yet.
func Load(usbMount string) (r Record, found bool, err error) {
	if usbMount == "" {
		return r, false, nil
	}
	data, err := os.ReadFile(filepath.Join(usbMount, File))
	if errors.Is(err, os.ErrNotExist) {
		return r, false, nil
	}
	if err != nil {
		return r, false, err
	}
	if err := json.Unmarshal(data, &r); err != nil {
		return r, false, fmt.Errorf("the escrow record on the stick is damaged: %w", err)
	}
	return r, true, nil
}

// Save writes the record to the stick.
func Save(usbMount string, r Record) error {
	if usbMount == "" {
		return errors.New("the stick's file system is not mounted")
	}
	data, _ := json.Marshal(r)
	return os.WriteFile(filepath.Join(usbMount, File), append(data, '\n'), 0o600)
}

// Change explains how now differs from the accepted record, or returns "" when it does not.
func Change(accepted, now Record) string {
	if accepted == now {
		return ""
	}
	switch {
	case !accepted.On() && now.On():
		return fmt.Sprintf("The server has turned escrow ON (policy %q, organisation key %s). Your organisation "+
			"wants to keep a copy of storage keys that lets its administrators read files.",
			now.Policy, Short(now.KeyFingerprint))
	case accepted.On() && !now.On():
		return fmt.Sprintf("The server has turned escrow off (policy %q). A copy sealed earlier may still exist: "+
			"escrow only really ends with a new storage key.", now.Policy)
	case accepted.KeyFingerprint != now.KeyFingerprint:
		return fmt.Sprintf("The server's escrow key changed from %s to %s. A copy sealed to the old key may still exist.",
			Short(accepted.KeyFingerprint), Short(now.KeyFingerprint))
	default:
		return fmt.Sprintf("The server's recovery policy changed from %q to %q.", accepted.Policy, now.Policy)
	}
}

// ConsentText explains, before anything is sealed, what agreeing to escrow means.
func ConsentText(fp string) string {
	return "Your organisation asks to keep a sealed copy of your storage key (escrow).\n" +
		"With it, its administrators can open and read ALL your files, and help you if you lose\n" +
		"your password. Organisation key: " + Short(fp) + "\n" +
		"Check this key against the one your organisation published. Nothing is sealed unless you agree."
}
