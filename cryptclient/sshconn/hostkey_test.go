package sshconn

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

func newKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

var addr = &net.TCPAddr{IP: net.ParseIP("203.0.113.5"), Port: 2207}

// ssh.Dial hands the callback "host:port". The pinned key must be found by host
// alone, and a different port later must not prompt again.
func TestHostKeyIsPinnedPerHostNotPerPort(t *testing.T) {
	key := newKey(t)
	hkm := NewHostKeyManager(t.TempDir())

	if err := hkm.GetCallback(func(string, string) bool { return true })("example.org:2201", addr, key); err != nil {
		t.Fatal(err)
	}

	prompted := false
	err := hkm.GetCallback(func(string, string) bool { prompted = true; return true })("example.org:2207", addr, key)
	if err != nil {
		t.Fatal(err)
	}
	if prompted {
		t.Fatal("prompted again for the same host on a different port")
	}
}

// The temporary known_hosts file must be real OpenSSH format: parse it with the
// OpenSSH known_hosts parser and verify the key against "host:port".
func TestKnownHostsFileIsValidOpenSSHFormat(t *testing.T) {
	key := newKey(t)
	hkm := NewHostKeyManager(t.TempDir())
	if err := hkm.GetCallback(func(string, string) bool { return true })("example.org:2207", addr, key); err != nil {
		t.Fatal(err)
	}

	path, err := writeKnownHosts("example.org", 2207, hkm)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(path)

	check, err := knownhosts.New(path)
	if err != nil {
		t.Fatalf("known_hosts not parseable: %v", err)
	}
	if err := check("example.org:2207", addr, key); err != nil {
		t.Fatalf("pinned key rejected: %v", err)
	}
	if err := check("example.org:2207", addr, newKey(t)); err == nil {
		t.Fatal("a different key was accepted")
	}
}

func TestChangedHostKeyIsRejected(t *testing.T) {
	hkm := NewHostKeyManager(t.TempDir())
	if err := hkm.GetCallback(func(string, string) bool { return true })("example.org:2201", addr, newKey(t)); err != nil {
		t.Fatal(err)
	}
	err := hkm.GetCallback(func(string, string) bool { return true })("example.org:2201", addr, newKey(t))
	if err == nil {
		t.Fatal("changed host key was accepted")
	}
}

// Stores written by older versions (fingerprint only, "host:port" names) keep
// working and are upgraded in place.
func TestLegacyEntryIsUpgraded(t *testing.T) {
	dir := t.TempDir()
	key := newKey(t)
	legacy := []*StoredHostKey{{
		Hostname: "example.org:2201", KeyType: key.Type(), Fingerprint: fingerprintSHA256(key),
	}}
	data, _ := json.Marshal(legacy)
	if err := os.WriteFile(filepath.Join(dir, HostKeyFile), data, 0600); err != nil {
		t.Fatal(err)
	}

	hkm := NewHostKeyManager(dir)
	if err := hkm.Load(); err != nil {
		t.Fatal(err)
	}
	prompted := false
	err := hkm.GetCallback(func(string, string) bool { prompted = true; return true })("example.org:2207", addr, key)
	if err != nil || prompted {
		t.Fatalf("legacy entry not accepted silently (err=%v prompted=%v)", err, prompted)
	}
	if _, err := writeKnownHosts("example.org", 2207, hkm); err != nil {
		t.Fatalf("legacy entry not upgraded: %v", err)
	}
}

func authorizedLine(key ssh.PublicKey) string {
	return string(ssh.MarshalAuthorizedKey(key))
}

// A key the API listed (over the pinned TLS connection) is pinned without asking.
func TestVouchedHostKeyIsPinnedWithoutPrompt(t *testing.T) {
	key := newKey(t)
	hkm := NewHostKeyManager(t.TempDir())
	if err := hkm.Vouch([]string{authorizedLine(newKey(t)), authorizedLine(key)}); err != nil {
		t.Fatal(err)
	}
	prompted := false
	if err := hkm.GetCallback(func(string, string) bool { prompted = true; return true })("example.org:2207", addr, key); err != nil {
		t.Fatal(err)
	}
	if prompted {
		t.Fatal("asked about a key the API vouched for")
	}
	if _, err := writeKnownHosts("example.org", 2207, hkm); err != nil {
		t.Fatalf("vouched key not pinned: %v", err)
	}
}

// When the API lists keys, any other key is refused and the user is not asked.
func TestUnvouchedHostKeyIsRefusedWithoutPrompt(t *testing.T) {
	hkm := NewHostKeyManager(t.TempDir())
	if err := hkm.Vouch([]string{authorizedLine(newKey(t))}); err != nil {
		t.Fatal(err)
	}
	prompted := false
	err := hkm.GetCallback(func(string, string) bool { prompted = true; return true })("example.org:2207", addr, newKey(t))
	if err == nil {
		t.Fatal("a key the API did not list was accepted")
	}
	if prompted {
		t.Fatal("the user was asked although the API listed the keys")
	}
}

// A rotated host key replaces the pin only when the API vouches for the new key.
func TestRotatedHostKeyIsAcceptedOnlyWhenVouched(t *testing.T) {
	dir := t.TempDir()
	old, rotated := newKey(t), newKey(t)
	hkm := NewHostKeyManager(dir)
	if err := hkm.GetCallback(func(string, string) bool { return true })("example.org:2201", addr, old); err != nil {
		t.Fatal(err)
	}

	again := NewHostKeyManager(dir)
	if err := again.Load(); err != nil {
		t.Fatal(err)
	}
	if err := again.Vouch([]string{authorizedLine(rotated)}); err != nil {
		t.Fatal(err)
	}
	if err := again.GetCallback(func(string, string) bool { return false })("example.org:2201", addr, rotated); err != nil {
		t.Fatalf("vouched rotated key refused: %v", err)
	}
	if err := again.GetCallback(func(string, string) bool { return true })("example.org:2201", addr, old); err == nil {
		t.Fatal("the old key was accepted after the pin moved to the new one")
	}
}

func TestVouchRejectsGarbage(t *testing.T) {
	if err := NewHostKeyManager("").Vouch([]string{"not a key"}); err == nil {
		t.Fatal("garbage accepted as a host key")
	}
}
