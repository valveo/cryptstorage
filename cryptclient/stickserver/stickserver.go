// Package stickserver remembers, on the stick, which server the stick belongs to, so that the client never
// uses or seals the stick against another one.
//
// A stick belongs to one server: its sealed key opens only with that server's stick secret. If the
// client is set to another server (a stale setting, a tray started earlier, a typo), sealing the stick there
// would tie it to the wrong server and the real one could no longer open it. So the stick records the server
// it was prepared or last used with, and the client stops with a clear message when they differ.
//
// The server is identified by its server_id (from /server-info), which the server derives from the same key
// that encrypts the stick secrets: it stays the same as long as the stick can open at all, also when the
// address changes or the operating system is reinstalled with a new SSH host key. Servers without stick
// secrets have no id; then the address is compared. The SSH host key fingerprints are kept for information
// (cryptclient diagnose), not compared: they change with a reinstall although the stick still works.
package stickserver

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"
)

// File is the record's name on the stick's data partition, next to the TLS pin and host keys.
const File = "cryptstorage.server"

// Record is the server the stick belongs to.
type Record struct {
	URL      string   `json:"url"`
	ServerID string   `json:"server_id,omitempty"`
	HostKeys []string `json:"ssh_host_key_fingerprints,omitempty"` // information only
}

// Load reads the record; nil without error when the stick has none yet (prepared by an older version) or
// its file system is not mounted.
func Load(mount string) (*Record, error) {
	if mount == "" {
		return nil, nil
	}
	b, err := os.ReadFile(filepath.Join(mount, File))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var r Record
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, fmt.Errorf("%s on the stick is damaged: %w", File, err)
	}
	return &r, nil
}

// Save writes the record.
func Save(mount string, r Record) error {
	if mount == "" {
		return errors.New("the stick's file system is not mounted")
	}
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(mount, File), append(b, '\n'), 0o600)
}

// OtherServerError means the stick belongs to another server than the one the client is set to.
type OtherServerError struct {
	StickURL  string // where the stick belongs
	ClientURL string // what the client is set to
	// SameAddress: the address is the stick's, but the server's identity changed (reinstalled without its
	// keys, or its accounts reset): the stick's key cannot open there any more
	SameAddress bool
}

func (e *OtherServerError) Error() string {
	if e.SameAddress {
		return fmt.Sprintf("The server at %s is no longer the one this stick was prepared with: it was set up "+
			"again without its old keys, or its accounts were reset. The key on the stick cannot open there.\n"+
			"Nothing was changed on the stick. Prepare it again with `cryptclient setup`.", e.ClientURL)
	}
	return fmt.Sprintf("This stick belongs to the server %s, but this computer is set to use %s.\n"+
		"Nothing was changed on the stick. Switch to the stick's server with `cryptclient server %s` "+
		"(or Change server... in the tray menu), or prepare the stick for this server with `cryptclient setup`: "+
		"the stick then no longer opens on the other one.", e.StickURL, e.ClientURL, e.StickURL)
}

// Check tells whether the stick with record r may be used with the server at url, whose /server-info gave
// serverID. A stick without a record passes: it gets one after its first successful connection.
func Check(r *Record, url, serverID string) error {
	if r == nil {
		return nil
	}
	sameURL := SameURL(r.URL, url)
	if r.ServerID == "" || serverID == "" {
		// a server without stick secrets has no id: the address is all there is. (A server that turned stick
		// secrets off at the stick's address passes here, and opening the key then says what is wrong.)
		if !sameURL {
			return &OtherServerError{StickURL: r.URL, ClientURL: url}
		}
		return nil
	}
	if r.ServerID != serverID {
		return &OtherServerError{StickURL: r.URL, ClientURL: url, SameAddress: sameURL}
	}
	return nil // the same server, possibly at a new address
}

// Updated is the record after a successful use of the stick with the server at url. Host keys are
// "type base64" lines from the API; nil keeps the earlier ones. changed tells whether it needs saving.
func Updated(r *Record, url, serverID string, hostKeys []string) (Record, bool) {
	var next Record
	if r != nil {
		next = *r
	}
	next.URL = url
	if serverID != "" {
		next.ServerID = serverID
	}
	if fps := fingerprints(hostKeys); len(fps) > 0 {
		next.HostKeys = fps
	}
	return next, r == nil || !equal(*r, next)
}

// SameURL compares two server addresses, ignoring the case of the scheme and host and a trailing slash.
func SameURL(a, b string) bool {
	return normalize(a) == normalize(b)
}

func normalize(u string) string {
	u = strings.TrimRight(strings.TrimSpace(u), "/")
	scheme, rest, ok := strings.Cut(u, "://")
	if !ok {
		return strings.ToLower(u)
	}
	host, path, _ := strings.Cut(rest, "/")
	if path != "" {
		path = "/" + path
	}
	return strings.ToLower(scheme) + "://" + strings.ToLower(host) + path
}

func fingerprints(lines []string) []string {
	var out []string
	for _, l := range lines {
		if k, _, _, _, err := ssh.ParseAuthorizedKey([]byte(l)); err == nil {
			out = append(out, ssh.FingerprintSHA256(k))
		}
	}
	return out
}

func equal(a, b Record) bool {
	if a.URL != b.URL || a.ServerID != b.ServerID || len(a.HostKeys) != len(b.HostKeys) {
		return false
	}
	for i := range a.HostKeys {
		if a.HostKeys[i] != b.HostKeys[i] {
			return false
		}
	}
	return true
}
