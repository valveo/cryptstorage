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
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"cryptclient/apiclient"
	"cryptclient/deps"
	"cryptclient/e2ee"
	"cryptclient/sshconn"
	"cryptclient/volume"
)

// Two devices of one user synchronise through the real API lock, SFTPGo, sshfs and gocryptfs
// (scripts/e2ee_integration.sh sets CRYPTSTORAGE_IT_URL). Both sync at the same moment, several times,
// with the same file changed on both: no version may be lost.
func TestIntegrationSync(t *testing.T) {
	url := os.Getenv("CRYPTSTORAGE_IT_URL")
	if url == "" {
		t.Skip("CRYPTSTORAGE_IT_URL not set")
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

	user := fmt.Sprintf("sy%d%d", os.Getpid(), time.Now().Unix()%100000)
	keys, _ := e2ee.Derive(user, "correct horse battery staple")
	api := apiclient.New(url, "", "")
	info, err := api.ServerInfo()
	if err != nil {
		t.Fatal(err)
	}
	if err := api.Register(user, user+"@example.com", keys.AuthKey); err != nil {
		t.Fatal(err)
	}
	if _, err := api.Login(user, keys.AuthKey, ""); err != nil {
		t.Fatal(err)
	}
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalECPrivateKey(priv)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	signer, _ := ssh.ParsePrivateKey(pemBytes)
	if err := api.RegisterKey(strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey()))), keys.AuthKey); err != nil {
		t.Fatal(err)
	}
	// The LAN test server (windows-selfhosted.yml) is deployed by hand and may be older than the client
	var apiErr *apiclient.APIError
	if _, err := api.AcquireSyncLock("probe-0123456789abcdef", "probe"); errors.As(err, &apiErr) && apiErr.Status == 404 {
		t.Skip("the server has no sync lock yet: deploy this branch to it (Deploy test server)")
	} else if err != nil {
		t.Fatal(err)
	}
	api.ReleaseSyncLock("probe-0123456789abcdef")
	storage, err := api.E2EEStorage()
	if err != nil {
		t.Fatal(err)
	}
	hkm := sshconn.NewHostKeyManager(t.TempDir())
	hkm.Load()
	connect := func() *volume.Conn {
		c, err := volume.Connect(volume.ConnectParams{Storage: storage, PEM: pemBytes, HKM: hkm,
			Confirm: func(string, string) bool { return true }})
		if err != nil {
			t.Fatalf("connect: %v", err)
		}
		return c
	}
	c := connect()
	if _, err := volume.Init(c, volume.InitParams{API: api, Info: info, Keys: keys}); err != nil {
		t.Fatal(err)
	}
	c.Close()

	// Two devices: each its own SSHFS connection, gocryptfs mount and local folder. They share the
	// login: the integration tests run in parallel from one address, and logins are rate limited.
	dir := t.TempDir()
	used := map[string]bool{}
	device := func(name string) *Syncer {
		a := apiclient.New(url, api.Token, "")
		conn := connect()
		plain := mountPoint(t, dir, name, used)
		if err := volume.Unlock(conn, keys, plain); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { e2ee.UnmountVolume(plain); conn.Close() })
		return New(Config{Rclone: rclone, Local: filepath.Join(dir, name), Remote: plain,
			WorkDir: filepath.Join(dir, name+"-work"), Holder: name + "-0123456789abcdef", HolderName: name,
			Interval: time.Second, Log: t.Logf}, a)
	}
	checkTwoDevices(t, device("laptop"), device("desktop"))
}

// checkTwoDevices lets two devices of one volume synchronise at the same moment, several times, with
// the same file changed on both: every version must survive (as the file or as a conflict copy).
func checkTwoDevices(t *testing.T, a, b *Syncer) {
	t.Helper()
	ctx := context.Background()
	once := func(s *Syncer) {
		t.Helper()
		if err := s.Once(ctx); err != nil {
			t.Fatal(err)
		}
	}
	once(a)
	once(b)
	os.WriteFile(filepath.Join(a.cfg.Local, "hello.txt"), []byte("hello from "+a.cfg.HolderName), 0o600)
	once(a)
	once(b)
	if got, _ := os.ReadFile(filepath.Join(b.cfg.Local, "hello.txt")); string(got) != "hello from "+a.cfg.HolderName {
		names := func(dir string) []string {
			entries, err := os.ReadDir(dir)
			if err != nil {
				return []string{err.Error()}
			}
			var n []string
			for _, e := range entries {
				n = append(n, e.Name())
			}
			return n
		}
		t.Fatalf("%s did not receive the file: %q\n%s sees %v in its volume, %s sees %v", b.cfg.HolderName, got,
			a.cfg.HolderName, names(a.cfg.Remote), b.cfg.HolderName, names(b.cfg.Remote))
	}
	for round := 0; round < 4; round++ {
		name := fmt.Sprintf("both%d.txt", round)
		os.WriteFile(filepath.Join(a.cfg.Local, name), []byte("first version"), 0o600)
		os.WriteFile(filepath.Join(b.cfg.Local, name), []byte("second version, longer"), 0o600)
		var wg sync.WaitGroup
		errs := make([]error, 2)
		for i, s := range []*Syncer{a, b} {
			wg.Add(1)
			go func(i int, s *Syncer) { defer wg.Done(); errs[i] = s.Once(ctx) }(i, s)
		}
		wg.Wait()
		if err := errors.Join(errs...); err != nil {
			t.Fatal(err)
		}
		once(a)
		once(b)
		for _, s := range []*Syncer{a, b} {
			files, _ := filepath.Glob(filepath.Join(s.cfg.Local, name+"*"))
			var all []string
			for _, f := range files {
				b, _ := os.ReadFile(f)
				all = append(all, string(b))
			}
			j := strings.Join(all, "|")
			if !strings.Contains(j, "first version") || !strings.Contains(j, "second version") {
				t.Fatalf("round %d: %s lost a version: %v", round, s.cfg.HolderName, all)
			}
		}
	}
}
