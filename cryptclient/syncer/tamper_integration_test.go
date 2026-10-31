package syncer

import (
	"context"
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
	"cryptclient/deps"
	"cryptclient/e2ee"
	"cryptclient/sshconn"
	"cryptclient/volume"
)

// What the synchronised folder does when a malicious server tampers with the ciphertext: does the
// damage reach the local copy? The test plays the server by changing the files in its storage directory
// (CRYPTSTORAGE_IT_CIPHER_BASE, set by scripts/e2ee_integration.sh) while the client is disconnected, then syncs.
func TestIntegrationSyncTamper(t *testing.T) {
	url := os.Getenv("CRYPTSTORAGE_IT_URL")
	base := os.Getenv("CRYPTSTORAGE_IT_CIPHER_BASE")
	if url == "" || base == "" {
		t.Skip("CRYPTSTORAGE_IT_URL and CRYPTSTORAGE_IT_CIPHER_BASE not set")
	}
	rclone := os.Getenv("CRYPTCLIENT_TEST_RCLONE")
	if rclone == "" {
		var err error
		if rclone, err = deps.RclonePath(); errors.Is(err, deps.ErrNoRclone) {
			rclone, err = deps.InstallRclone(t.Logf)
		}
		if err != nil {
			t.Fatal(err)
		}
	}

	// An account with a volume. The other integration tests run at the same time from the same address
	// and share the API's rate limits.
	api := apiclient.New(url, "", "")
	info, err := api.ServerInfo()
	if err != nil {
		t.Fatal(err)
	}
	user := fmt.Sprintf("st%d%d", os.Getpid(), time.Now().Unix()%100000)
	keys, _ := e2ee.Derive(user, "correct horse battery staple")
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
	connect := func() *volume.Conn {
		t.Helper()
		c, err := volume.Connect(volume.ConnectParams{Storage: storage, PEM: pemBytes, HKM: hkm,
			Confirm: func(string, string) bool { return true }})
		if err != nil {
			t.Fatalf("connect: %v", err)
		}
		return c
	}
	c := connect()
	if _, err := volume.Init(c, volume.InitParams{API: api, Info: info, Keys: keys,
		ConsentEscrow: func(string) bool { return false }}); err != nil {
		t.Fatal(err)
	}
	c.Close()
	server := filepath.Join(base, storage.SSHUser, "data")

	// One device. The volume is mounted at the same place every time, so rclone keeps its listings.
	dir := t.TempDir()
	plain := mountPoint(t, dir, "laptop", map[string]bool{})
	local := filepath.Join(dir, "laptop")
	var warned []string
	s := New(Config{Rclone: rclone, Local: local, Remote: plain, WorkDir: filepath.Join(dir, "work"),
		Holder: "laptop-0123456789abcdef", HolderName: "laptop", Interval: time.Second, Log: t.Logf,
		Warn: func(m string) { t.Log(m); warned = append(warned, m) }}, api)
	mounted := func(fn func()) {
		t.Helper()
		c := connect()
		defer c.Close()
		if err := volume.Unlock(c, keys, plain); err != nil {
			t.Fatal(err)
		}
		defer e2ee.UnmountVolume(plain)
		fn()
	}
	sync := func() string {
		t.Helper()
		var err error
		mounted(func() { err = s.Once(context.Background()) })
		switch {
		case err == nil:
			return "ok"
		case errors.Is(err, ErrTooManyDeletes):
			return "safety stop"
		case errors.Is(err, ErrNeedsResync):
			return "stopped, needs resync"
		default:
			t.Logf("sync: %v", err)
			return "error"
		}
	}
	localFile := func(name string) string {
		b, err := os.ReadFile(filepath.Join(local, name))
		if err != nil {
			return "missing"
		}
		return fmt.Sprintf("%q", string(b))
	}
	// what the trash holds of a file, from the newest run that has it
	trashed := func(name string) string {
		runs, _ := filepath.Glob(filepath.Join(local, TrashName, "*", name))
		if len(runs) == 0 {
			return "missing"
		}
		sort.Strings(runs)
		return fmt.Sprintf("%q", string(readFile(t, runs[len(runs)-1])))
	}
	warnedAbout := func(name string) string {
		for _, w := range warned {
			if strings.Contains(w, name) {
				return "named"
			}
		}
		return "not named"
	}

	// The files, created in the volume one at a time so each one's ciphertext name is known
	cipher := map[string]string{}
	mounted(func() {
		create := func(name, content string) {
			parent := server
			if d := filepath.Dir(name); d != "." {
				parent = cipher[d]
			}
			before := map[string]bool{}
			for _, n := range listNames(parent) {
				before[n] = true
			}
			var err error
			if content == "" {
				err = os.Mkdir(filepath.Join(plain, name), 0o700)
			} else {
				err = os.WriteFile(filepath.Join(plain, name), []byte(content), 0o600)
			}
			if err != nil {
				t.Fatal(err)
			}
			for _, n := range listNames(parent) {
				if !before[n] {
					cipher[name] = filepath.Join(parent, n)
				}
			}
			if cipher[name] == "" {
				t.Fatalf("no ciphertext entry appeared for %s", name)
			}
		}
		for _, f := range []string{"deleted.txt", "rollback.txt", "flipped.txt"} {
			create(f, "first version of "+f)
		}
		create("many", "")
		for i := 0; i < 8; i++ {
			create(fmt.Sprintf("many/f%d.txt", i), fmt.Sprintf("file %d", i))
		}
	})
	if got := sync(); got != "ok" {
		t.Fatalf("first sync: %s", got)
	}
	v1 := readFile(t, cipher["rollback.txt"])
	time.Sleep(1100 * time.Millisecond) // a newer modification time than version 1, past --modify-window
	if err := os.WriteFile(filepath.Join(local, "rollback.txt"), []byte("second version"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := sync(); got != "ok" {
		t.Fatalf("sync of the second version: %s", got)
	}

	// 1. deleted on the server: the sync deletes the local copy too, into the trash
	os.Remove(cipher["deleted.txt"])
	tamperReport(t, "deleted: sync", "ok", sync())
	tamperReport(t, "deleted: local copy", "missing", localFile("deleted.txt"))
	tamperReport(t, "deleted: in the trash", `"first version of deleted.txt"`, trashed("deleted.txt"))

	// 2. an older version put back: the local copy is rolled back as well, the newer one is in the trash
	writeFile(t, cipher["rollback.txt"], v1)
	tamperReport(t, "rollback: sync", "ok", sync())
	tamperReport(t, "rollback: local copy", `"first version of rollback.txt"`, localFile("rollback.txt"))
	tamperReport(t, "rollback: in the trash", `"second version"`, trashed("rollback.txt"))

	// 3. a directory's IV replaced, so most files vanish at once: rclone's safety stop keeps the local
	// copies; with the IV put back the next sync goes on as before
	diriv := filepath.Join(cipher["many"], "gocryptfs.diriv")
	iv := readFile(t, diriv)
	writeFile(t, diriv, readFile(t, filepath.Join(server, "gocryptfs.diriv"))) // a valid IV, but another directory's
	tamperReport(t, "many vanish: sync", "safety stop", sync())
	tamperReport(t, "many vanish: local copy", `"file 0"`, localFile("many/f0.txt"))
	writeFile(t, diriv, iv)
	tamperReport(t, "many back: sync", "ok", sync())

	// 4. a changed byte: the file cannot be read. The client names it, leaves it out and syncs the rest;
	// the local copy stays as it was
	b := readFile(t, cipher["flipped.txt"])
	b[len(b)/2] ^= 0x01
	writeFile(t, cipher["flipped.txt"], b)
	if err := os.WriteFile(filepath.Join(local, "new.txt"), []byte("made after the damage"), 0o600); err != nil {
		t.Fatal(err)
	}
	tamperReport(t, "flipped: sync", "ok", sync())
	tamperReport(t, "flipped: user told", "named", warnedAbout("flipped.txt"))
	tamperReport(t, "flipped: local copy", `"first version of flipped.txt"`, localFile("flipped.txt"))
	tamperReport(t, "flipped: others kept", `"file 0"`, localFile("many/f0.txt"))
	tamperReport(t, "flipped: next sync", "ok", sync())
	var uploaded string
	mounted(func() {
		b, err := os.ReadFile(filepath.Join(plain, "new.txt"))
		uploaded = fmt.Sprintf("%q / %v", b, err)
	})
	tamperReport(t, "flipped: others sync", `"made after the damage" / <nil>`, uploaded)

	// 5. the user replaces the damaged copy with the local one
	s.cfg.ReplaceUnreadable = true
	tamperReport(t, "replaced: sync", "ok", sync())
	tamperReport(t, "replaced: sync again", "ok", sync())
	var repaired string
	mounted(func() {
		b, err := os.ReadFile(filepath.Join(plain, "flipped.txt"))
		repaired = fmt.Sprintf("%q / %v", b, err)
	})
	tamperReport(t, "replaced: storage copy", `"first version of flipped.txt" / <nil>`, repaired)
	var trashOnServer error
	mounted(func() { _, trashOnServer = os.Stat(filepath.Join(plain, TrashName)) })
	tamperReport(t, "trash stays local", "true", fmt.Sprint(errors.Is(trashOnServer, os.ErrNotExist)))
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

// tamperReport logs what the user sees and fails when it is not what SECURITY.md describes.
func tamperReport(t *testing.T, name, want, observed string) {
	t.Helper()
	t.Logf("%-24s %s", name, observed)
	if want != observed {
		t.Errorf("%s: the behaviour changed: want %s, got %s (update SECURITY.md)", name, want, observed)
	}
}

func listNames(dir string) []string {
	entries, _ := os.ReadDir(dir)
	var n []string
	for _, e := range entries {
		n = append(n, e.Name())
	}
	sort.Strings(n)
	return n
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func writeFile(t *testing.T, path string, b []byte) {
	t.Helper()
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}
