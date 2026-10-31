package volume

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"cryptclient/apiclient"
	"cryptclient/e2ee"
	"cryptclient/sshconn"
)

// A malicious server tampers with the ciphertext (design-e2ee sections 3 and 10). gocryptfs does not
// prevent this; the test records what the user sees in each case, so SECURITY.md can say it and a change in
// behaviour shows up. Runs in scripts/e2ee_integration.sh, which sets CRYPTSTORAGE_IT_CIPHER_BASE: the test
// plays the server by changing the files in the server's storage directory while the client is disconnected.
func TestIntegrationTamper(t *testing.T) {
	url := os.Getenv("CRYPTSTORAGE_IT_URL")
	base := os.Getenv("CRYPTSTORAGE_IT_CIPHER_BASE")
	if url == "" || base == "" {
		t.Skip("CRYPTSTORAGE_IT_URL and CRYPTSTORAGE_IT_CIPHER_BASE not set")
	}
	tv := newTamperVolume(t, url, base)

	// The files, each created alone so its ciphertext name can be found on the server
	big := strings.Repeat("0123456789abcdef", 1024) // 16 KiB: four gocryptfs blocks
	cipher := map[string]string{}                   // plaintext path -> ciphertext path on the server
	tv.mounted(func(plain string) {
		for _, d := range []string{"moved", "diriv"} {
			tv.create(plain, d, "", cipher)
		}
		for _, f := range []struct{ name, content string }{
			{"a.txt", "content of a"},
			{"b.txt", "content of b, a little longer"},
			{"moved/m.txt", "moved file"},
			{"diriv/d.txt", "file under a replaced diriv"},
			{"rollback.txt", "version 1"},
			{"truncated.bin", big},
			{"flipped.bin", big},
			{"deleted.txt", "to be deleted"},
		} {
			tv.create(plain, f.name, f.content, cipher)
		}
	})
	v1 := tv.read(cipher["rollback.txt"])
	tv.mounted(func(plain string) {
		if err := os.WriteFile(filepath.Join(plain, "rollback.txt"), []byte("version 2, newer"), 0o600); err != nil {
			t.Fatal(err)
		}
	})

	// The server does its work
	a, b := tv.read(cipher["a.txt"]), tv.read(cipher["b.txt"])
	tv.write(cipher["a.txt"], b)
	tv.write(cipher["b.txt"], a)
	if err := os.Rename(cipher["moved/m.txt"], filepath.Join(tv.dir, filepath.Base(cipher["moved/m.txt"]))); err != nil {
		t.Fatal(err)
	}
	tv.write(filepath.Join(cipher["diriv"], "gocryptfs.diriv"), tv.read(filepath.Join(cipher["moved"], "gocryptfs.diriv")))
	tv.write(cipher["rollback.txt"], v1)
	if err := os.Truncate(cipher["truncated.bin"], int64(len(tv.read(cipher["truncated.bin"]))-100)); err != nil {
		t.Fatal(err)
	}
	flipped := tv.read(cipher["flipped.bin"])
	flipped[len(flipped)/2] ^= 0x01
	tv.write(cipher["flipped.bin"], flipped)
	if err := os.Remove(cipher["deleted.txt"]); err != nil {
		t.Fatal(err)
	}

	// What the user sees
	tv.mounted(func(plain string) {
		got := func(name string) (string, error) {
			b, err := os.ReadFile(filepath.Join(plain, name))
			return string(b), err
		}
		report := func(name, want, observed string) { tamperReport(t, name, want, observed) }
		describe := func(name string) string {
			s, err := got(name)
			switch {
			case os.IsNotExist(err):
				return "missing"
			case err != nil:
				return "read error"
			default:
				return "reads " + fmt.Sprintf("%q", trim(s))
			}
		}
		// swapped within one directory: not detected, the contents trade places
		report("a.txt", `reads "content of b, a little longer"`, describe("a.txt"))
		report("b.txt", `reads "content of a"`, describe("b.txt"))
		// moved to another directory: its name no longer decrypts there, so it is gone from both
		report("moved/m.txt", "missing", describe("moved/m.txt"))
		report("root listing", strings.Join([]string{".secdisk-canary", "a.txt", "b.txt", "diriv", "flipped.bin",
			"moved", "rollback.txt", "truncated.bin"}, ","), strings.Join(names(t, plain), ","))
		// a directory's IV replaced: none of its names decrypt, the directory looks empty
		report("diriv listing", "", strings.Join(names(t, filepath.Join(plain, "diriv")), ","))
		// an older version put back: not detected
		report("rollback.txt", `reads "version 1"`, describe("rollback.txt"))
		// cut short or a changed byte: the read fails (AES-GCM), nothing wrong is returned
		report("truncated.bin", "read error", describe("truncated.bin"))
		report("flipped.bin", "read error", describe("flipped.bin"))
		// deleted: simply gone
		report("deleted.txt", "missing", describe("deleted.txt"))
	})

	// The volume's own files. An old gocryptfs.conf put back after a password change: the new password
	// is refused and the old one opens the volume again (the master key never changed).
	confPath := filepath.Join(tv.dir, "gocryptfs.conf")
	oldConf := tv.read(confPath)
	newKeys, _ := e2ee.Derive(tv.user, "a changed password phrase")
	c := tv.connect()
	if _, err := Rewrap(c, tv.keys.VolumePassphrase, newKeys.VolumePassphrase); err != nil {
		t.Fatal(err)
	}
	c.Close()
	tv.write(confPath, oldConf)
	opens := func(k *e2ee.Keys) string {
		c := tv.connect()
		defer c.Close()
		plain := plainDir(t)
		if err := Unlock(c, k, plain); err != nil {
			return "refused"
		}
		e2ee.UnmountVolume(plain)
		return "opens"
	}
	tamperReport(t, "old conf, new password", "refused", opens(newKeys))
	tamperReport(t, "old conf, old password", "opens", opens(tv.keys))

	// The check file replaced by another valid file: unlocking does not notice, but recovery with the right
	// code then refuses, because the check file reads back with the wrong content
	var canary string
	known := map[string]bool{}
	for _, p := range cipher {
		known[filepath.Base(p)] = true
	}
	for _, n := range names(t, tv.dir) {
		if !known[n] && !strings.HasPrefix(n, "gocryptfs.") && !strings.HasPrefix(n, ".") {
			canary = filepath.Join(tv.dir, n)
		}
	}
	if canary == "" {
		t.Fatal("the check file's ciphertext was not found")
	}
	tv.write(canary, tv.read(cipher["rollback.txt"]))
	tamperReport(t, "canary, unlock", "opens", opens(tv.keys))
	mk, err := e2ee.ParseRecoveryCode(tv.recoveryCode)
	if err != nil {
		t.Fatal(err)
	}
	c = tv.connect()
	recovered := "accepted"
	if _, err := Recover(c, mk, newKeys.VolumePassphrase); err != nil {
		recovered = "refused"
	}
	c.Close()
	tamperReport(t, "canary, recovery", "refused", recovered)
}

// tamperReport logs what the user sees and fails when it is not what SECURITY.md describes.
func tamperReport(t *testing.T, name, want, observed string) {
	t.Helper()
	t.Logf("%-24s %s", name, observed)
	if want != observed {
		t.Errorf("%s: the behaviour changed: want %q, got %q (update SECURITY.md)", name, want, observed)
	}
}

func trim(s string) string {
	if len(s) > 40 {
		return s[:40] + "..."
	}
	return s
}

func names(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return []string{"error: " + err.Error()}
	}
	var n []string
	for _, e := range entries {
		n = append(n, e.Name())
	}
	sort.Strings(n)
	return n
}

// tamperVolume is one account with a fresh volume, and direct access to its ciphertext on the server.
type tamperVolume struct {
	t            *testing.T
	user         string
	keys         *e2ee.Keys
	recoveryCode string
	dir          string // the volume's ciphertext directory on the server
	connect      func() *Conn
}

func newTamperVolume(t *testing.T, url, base string) *tamperVolume {
	t.Helper()
	api := apiclient.New(url, "", "")
	info, err := api.ServerInfo()
	if err != nil {
		t.Fatal(err)
	}
	user := fmt.Sprintf("tm%d%d", os.Getpid(), time.Now().Unix()%100000)
	keys, _ := e2ee.Derive(user, "correct horse battery staple")
	// The other integration tests run at the same time from the same address and share the API's rate limits
	if err := waitRateLimit(t, func() error { return api.Register(user, user+"@example.com", keys.AuthKey) }); err != nil {
		t.Fatal(err)
	}
	if err := waitRateLimit(t, func() error { _, err := api.Login(user, keys.AuthKey, ""); return err }); err != nil {
		t.Fatal(err)
	}
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalECPrivateKey(priv)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	signer, _ := ssh.ParsePrivateKey(pemBytes)
	pub := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
	if err := waitRateLimit(t, func() error { return api.RegisterKey(pub, keys.AuthKey) }); err != nil {
		t.Fatal(err)
	}
	storage, err := api.E2EEStorage()
	if err != nil {
		t.Fatal(err)
	}
	hkm := sshconn.NewHostKeyManager(t.TempDir())
	hkm.Load()
	tv := &tamperVolume{t: t, user: user, keys: keys, dir: filepath.Join(base, storage.SSHUser, "data")}
	tv.connect = func() *Conn {
		t.Helper()
		c, err := Connect(ConnectParams{Storage: storage, PEM: pemBytes, HKM: hkm,
			Confirm: func(string, string) bool { return true }})
		if err != nil {
			t.Fatalf("connect: %v", err)
		}
		return c
	}
	c := tv.connect()
	defer c.Close()
	res, err := Init(c, InitParams{API: api, Info: info, Keys: keys,
		ConsentEscrow: func(string) bool { return false }})
	if err != nil {
		t.Fatal(err)
	}
	if res.RecoveryCode == "" {
		t.Skip("the server's recovery policy gives no recovery code")
	}
	tv.recoveryCode = res.RecoveryCode
	return tv
}

// waitRateLimit runs fn again while the API answers 429, for at most two minutes.
func waitRateLimit(t *testing.T, fn func() error) error {
	t.Helper()
	for deadline := time.Now().Add(2 * time.Minute); ; {
		err := fn()
		var apiErr *apiclient.APIError
		if !errors.As(err, &apiErr) || apiErr.Status != 429 || time.Now().After(deadline) {
			return err
		}
		t.Log("rate limited by the API, waiting")
		time.Sleep(10 * time.Second)
	}
}

// mounted connects, opens the volume, runs fn on the plaintext view and disconnects again.
func (tv *tamperVolume) mounted(fn func(plain string)) {
	tv.t.Helper()
	c := tv.connect()
	defer c.Close()
	plain := plainDir(tv.t)
	if err := Unlock(c, tv.keys, plain); err != nil {
		tv.t.Fatal(err)
	}
	defer e2ee.UnmountVolume(plain)
	fn(plain)
}

// create makes a file (or, with no content and no extension, a directory) and records which new
// ciphertext entry appeared on the server for it.
func (tv *tamperVolume) create(plain, name, content string, cipher map[string]string) {
	tv.t.Helper()
	parent := tv.dir
	if d := filepath.Dir(name); d != "." {
		parent = cipher[d]
	}
	before := map[string]bool{}
	for _, n := range names(tv.t, parent) {
		before[n] = true
	}
	p := filepath.Join(plain, name)
	var err error
	if content == "" && filepath.Ext(name) == "" {
		err = os.Mkdir(p, 0o700)
	} else {
		err = os.WriteFile(p, []byte(content), 0o600)
	}
	if err != nil {
		tv.t.Fatal(err)
	}
	var added []string
	for _, n := range names(tv.t, parent) {
		if !before[n] {
			added = append(added, n)
		}
	}
	if len(added) != 1 {
		tv.t.Fatalf("%s: expected one new ciphertext entry, got %v", name, added)
	}
	cipher[name] = filepath.Join(parent, added[0])
}

func (tv *tamperVolume) read(path string) []byte {
	tv.t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		tv.t.Fatal(err)
	}
	return b
}

func (tv *tamperVolume) write(path string, b []byte) {
	tv.t.Helper()
	if err := os.WriteFile(path, b, 0o600); err != nil {
		tv.t.Fatal(err)
	}
}
