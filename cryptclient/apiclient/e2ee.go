package apiclient

import (
	"fmt"
	"time"
)

// Calls used by end-to-end encrypted storage (docs/design-e2ee.md). In this mode the "password"
// sent to the server is the login key derived by the client (e2ee.Derive), never the password.

// ServerInfo from GET /server-info.
type ServerInfo struct {
	StorageMode     string  `json:"storage_mode"`
	Version         string  `json:"version"` // the build the server runs; empty from older servers
	RecoveryPolicy  string  `json:"recovery_policy"`
	EscrowPublicKey *string `json:"escrow_public_key"`
	// EscrowKeyFingerprint is informational: the client computes its own from EscrowPublicKey.
	EscrowKeyFingerprint *string `json:"escrow_key_fingerprint"`
	// ServerID tells servers apart; it lasts as long as the server's stick secrets. Empty from servers
	// without stick secrets, and from older ones.
	ServerID string `json:"server_id"`
}

// E2EEStorage from GET /storage/e2ee: where to connect for the ciphertext.
type E2EEStorage struct {
	SSHHost string `json:"ssh_host"`
	SSHPort int    `json:"ssh_port"`
	SSHUser string `json:"ssh_user"`
	// SSHHostKeys are the SFTP service's host keys ("type base64"); empty on servers that do not
	// report them, and then the client asks the user to confirm the key on the first connection.
	SSHHostKeys []string `json:"ssh_host_keys"`
	QuotaBytes  int64    `json:"quota_bytes"`
	UsedBytes   int64    `json:"used_bytes"`
}

func (c *Client) ServerInfo() (*ServerInfo, error) {
	var r ServerInfo
	if err := c.get("/server-info", &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// Register creates the account. loginKey is e2ee.Keys.AuthKey.
func (c *Client) Register(username, email, loginKey string) error {
	var r map[string]interface{}
	return c.post("/auth/register", map[string]string{
		"username": username, "email": email, "password": loginKey,
	}, &r)
}

// KeyPendingError means the server accepted a new SSH key but, as a safety measure, activates
// it only later (docs/design-factors.md): until then the old key keeps working and the
// owner can cancel from the e-mail. Asking again for the same key is harmless.
type KeyPendingError struct {
	EffectiveAt time.Time
}

func (e *KeyPendingError) Error() string {
	return fmt.Sprintf("the new stick starts working on %s (a safety wait for a replaced key)", e.when())
}

// when is the activation time in the computer's own time zone.
func (e *KeyPendingError) when() string {
	return e.EffectiveAt.Local().Format("2.1.2006 at 15:04 MST")
}

// Explain tells the user, line by line, that the wait is a normal step and what to do. It is
// meant to be shown as news, not as a failure: everything the command could do is done.
func (e *KeyPendingError) Explain() []string {
	wait := ""
	if h := int(time.Until(e.EffectiveAt).Round(time.Hour).Hours()); h >= 1 {
		wait = fmt.Sprintf(", about %d hours from now", h)
	}
	return []string{
		fmt.Sprintf("✓ The new stick is registered. For your safety it starts working on %s%s.", e.when(), wait),
		"  Your account already had a key, and replacing one always waits: this stops someone who has",
		"  learnt your password from taking over your account. Until then your old key keeps working.",
		"  We sent an e-mail to your address: if you did not do this, cancel the change from the link in it.",
		"  After that time, insert the stick and run: cryptclient connect",
	}
}

// RegisterKey stores the SSH public key (the server provisions it into the SFTP service).
// The first key of an account, or the key that is already active, works at once; replacing a
// key returns *KeyPendingError.
func (c *Client) RegisterKey(pubKey, loginKey string) error {
	var r struct {
		Pending     bool   `json:"pending"`
		EffectiveAt string `json:"effective_at"`
	}
	if err := c.put("/users/me/ssh-key", map[string]string{
		"ssh_public_key": pubKey, "password": loginKey,
	}, &r); err != nil {
		return err
	}
	if !r.Pending {
		return nil
	}
	// The server sends UTC without a zone ("2026-10-26T20:15:00", maybe with fractions)
	at, err := time.Parse(time.RFC3339, r.EffectiveAt)
	if err != nil {
		at, _ = time.Parse("2006-01-02T15:04:05", r.EffectiveAt)
	}
	return &KeyPendingError{EffectiveAt: at}
}

func (c *Client) E2EEStorage() (*E2EEStorage, error) {
	var r E2EEStorage
	if err := c.get("/storage/e2ee", &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// PutRecoveryVerifier stores the proof used later to reset the login key (e2ee.RecoveryProof).
func (c *Client) PutRecoveryVerifier(proof string) error {
	var r map[string]string
	return c.put("/users/me/recovery-verifier", map[string]string{"proof": proof}, &r)
}

// PutEscrow stores the master key sealed to the organisation's key (opaque to the server).
func (c *Client) PutEscrow(blobHex string) error {
	var r map[string]string
	return c.put("/users/me/escrow", map[string]string{"blob": blobHex}, &r)
}

// RecoverE2EE resets the login key with the recovery proof. No login needed. An account with
// two-factor also needs a code (or backup code): without one it returns ErrTOTPRequired.
func (c *Client) RecoverE2EE(username, proof, newLoginKey, totpCode string) error {
	var r map[string]string
	return totpErr(c.post("/auth/recover-e2ee", withCode(map[string]string{
		"username": username, "proof": proof, "new_password": newLoginKey,
	}, totpCode), &r))
}

// ChangeLoginKey replaces the login key (password change). All sessions end. A login that passed
// two-factor a few minutes ago is enough; otherwise it returns ErrTOTPRequired and wants a code.
func (c *Client) ChangeLoginKey(oldKey, newKey, totpCode string) error {
	var r map[string]string
	return totpErr(c.post("/users/me/password", withCode(map[string]string{
		"current_password": oldKey, "new_password": newKey,
	}, totpCode), &r))
}

func withCode(body map[string]string, totpCode string) map[string]string {
	if totpCode != "" {
		body["totp_code"] = totpCode
	}
	return body
}
