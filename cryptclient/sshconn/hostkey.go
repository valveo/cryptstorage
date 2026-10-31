package sshconn

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"

	"golang.org/x/crypto/ssh"
)

// HostKeyStore stores the server's host key on the stick on the first
// connection and verifies it every time after that.
//
// The file is stored on the USB stick's FAT32 partition as a normal file,
// because the host key is not secret – it is public information.
// What matters is that it is bound to this stick.

// HostKeyFile is the file name stored in the root of the stick.
const HostKeyFile = "cryptstorage.hostkey"

// StoredHostKey contains the stored host key data.
type StoredHostKey struct {
	Hostname    string `json:"hostname"` // host only, without port (see normalizeHost)
	KeyType     string `json:"key_type"`
	Fingerprint string `json:"fingerprint"` // SHA256 base64, shown to the user
	// PublicKey is the base64 of the marshaled public key. OpenSSH's known_hosts
	// needs the key itself, a fingerprint is not enough. Entries written by older
	// versions lack it and are upgraded the next time the same key is seen.
	PublicKey string `json:"public_key,omitempty"`
}

// normalizeHost strips the port. ssh.Dial passes "host:port" to the host key
// callback, but the key belongs to the user's container, which is reachable on
// whichever port is free at login. Keying by "host:port" made the stored key
// unfindable by host alone and prompted again every time the port changed.
func normalizeHost(addr string) string {
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return host
	}
	return addr
}

// HostKeyManager manages storing and verifying host keys.
type HostKeyManager struct {
	storePath string // path to the hostkey file
	stored    map[string]*StoredHostKey
	// vouched holds the fingerprints of the keys the API listed for the SFTP service. The API is
	// reached over the pinned TLS connection, so these replace the "Trust this key?" question.
	vouched map[string]bool
}

// NewHostKeyManager creates a new manager.
// usbMountPath is the root of the stick's file system, e.g. /media/user/CRYPTKEY/. Empty means
// it is not mounted: keys are then kept in memory only, never in some other directory.
func NewHostKeyManager(usbMountPath string) *HostKeyManager {
	m := &HostKeyManager{stored: make(map[string]*StoredHostKey)}
	if usbMountPath != "" {
		m.storePath = filepath.Join(usbMountPath, HostKeyFile)
	}
	return m
}

// Persistent tells whether accepted keys are remembered on the stick.
func (m *HostKeyManager) Persistent() bool {
	return m.storePath != ""
}

// Vouch records the SFTP host keys that the API reported (authorized_keys format, "type base64").
// Once any key is vouched for, an unknown host key is pinned without asking only if it is one of
// them, and any other key is refused. With none, the first connection asks the user as before.
func (m *HostKeyManager) Vouch(keys []string) error {
	for _, line := range keys {
		key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
		if err != nil {
			return fmt.Errorf("the server listed an invalid SSH host key: %w", err)
		}
		if m.vouched == nil {
			m.vouched = make(map[string]bool)
		}
		m.vouched[fingerprintSHA256(key)] = true
	}
	return nil
}

// Load loads the stored host keys from the file.
func (m *HostKeyManager) Load() error {
	if m.storePath == "" {
		return nil
	}
	data, err := os.ReadFile(m.storePath)
	if os.IsNotExist(err) {
		return nil // not stored yet, ok
	}
	if err != nil {
		return fmt.Errorf("reading host key store: %w", err)
	}

	var keys []*StoredHostKey
	if err := json.Unmarshal(data, &keys); err != nil {
		return fmt.Errorf("parsing host key store: %w", err)
	}

	for _, k := range keys {
		k.Hostname = normalizeHost(k.Hostname)
		m.stored[k.Hostname] = k
	}
	return nil
}

// Save saves the host keys to the file.
func (m *HostKeyManager) Save() error {
	if m.storePath == "" {
		return nil
	}
	keys := make([]*StoredHostKey, 0, len(m.stored))
	for _, k := range m.stored {
		keys = append(keys, k)
	}

	data, err := json.MarshalIndent(keys, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(m.storePath, data, 0600)
}

// GetCallback returns an ssh.HostKeyCallback that:
//   - On first connection: pins the key if the API vouched for it (see Vouch), refuses it if the
//     API vouched for other keys only, and otherwise asks the user for confirmation
//   - On later connections: checks that the key matches the stored one; a different key is
//     accepted (and replaces the pin) only if the API vouched for it, so a server whose
//     host key was rotated does not lock its users out
func (m *HostKeyManager) GetCallback(confirmFn func(hostname, fingerprint string) bool) ssh.HostKeyCallback {
	return func(hostname string, _ net.Addr, key ssh.PublicKey) error {
		fingerprint := fingerprintSHA256(key)
		hostname = normalizeHost(hostname)

		existing, known := m.stored[hostname]

		if !known {
			switch {
			case m.vouched[fingerprint]:
				// the API listed it over the pinned TLS connection: nothing to ask
			case len(m.vouched) > 0:
				return fmt.Errorf(
					"the SFTP server %s presented the host key %s, which is not one the server's API lists.\n"+
						"  This could indicate a man-in-the-middle attack.", hostname, fingerprint)
			case !confirmFn(hostname, fingerprint):
				return fmt.Errorf("host key rejected by user")
			}
			m.pin(hostname, key, fingerprint)
			fmt.Printf("✓ Host key saved for %s\n", hostname)
			return nil
		}

		// Check the stored key
		if existing.Fingerprint != fingerprint {
			if m.vouched[fingerprint] {
				m.pin(hostname, key, fingerprint)
				fmt.Printf("✓ The server's host key changed; the server's API confirmed the new key %s\n", fingerprint)
				return nil
			}
			return fmt.Errorf(
				"HOST KEY MISMATCH for %s!\n"+
					"  Expected:  %s\n"+
					"  Got:       %s\n"+
					"  This could indicate a man-in-the-middle attack.\n"+
					"  If the server was reinstalled, delete %s and reconnect.",
				hostname, existing.Fingerprint, fingerprint, HostKeyFile,
			)
		}

		// Upgrade an entry written before PublicKey was stored
		if existing.PublicKey == "" {
			existing.KeyType = key.Type()
			existing.PublicKey = base64.StdEncoding.EncodeToString(key.Marshal())
			if err := m.Save(); err != nil {
				fmt.Fprintf(os.Stderr, "Warning: could not update host key store: %v\n", err)
			}
		}

		return nil
	}
}

// pin stores key as the host key of hostname and saves the store on the stick.
func (m *HostKeyManager) pin(hostname string, key ssh.PublicKey, fingerprint string) {
	m.stored[hostname] = &StoredHostKey{
		Hostname:    hostname,
		KeyType:     key.Type(),
		Fingerprint: fingerprint,
		PublicKey:   base64.StdEncoding.EncodeToString(key.Marshal()),
	}
	if err := m.Save(); err != nil {
		// Warn but do not block the connection
		fmt.Fprintf(os.Stderr, "Warning: could not save host key: %v\n", err)
	}
}

// fingerprintSHA256 computes the SHA256 fingerprint of an SSH key (same format as ssh-keygen).
func fingerprintSHA256(key ssh.PublicKey) string {
	hash := sha256.Sum256(key.Marshal())
	return "SHA256:" + base64.StdEncoding.EncodeToString(hash[:])
}
