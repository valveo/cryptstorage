package volume

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"cryptclient/apiclient"
	"cryptclient/e2ee"
	"cryptclient/sshconn"
)

// An account and a volume made by a v0.1.0 client (key derivation version 1) move over to version 2:
// the volume is re-wrapped when the new client unlocks it, the login key when it asks the server to.
// The data is not touched. Run by scripts/e2ee_integration.sh.
func TestIntegrationKdfMove(t *testing.T) {
	url := os.Getenv("CRYPTSTORAGE_IT_URL")
	if url == "" {
		t.Skip("CRYPTSTORAGE_IT_URL not set")
	}
	api := apiclient.New(url, "", "")
	info, err := api.ServerInfo()
	if err != nil {
		t.Fatal(err)
	}
	if info.KdfSalt == "" || info.KdfVersion != 2 {
		t.Fatalf("the server publishes no key derivation salt: %+v", info)
	}
	const password = "correct horse battery staple"
	user := fmt.Sprintf("kd%d%d", os.Getpid(), time.Now().Unix()%100000)

	// 1. as v0.1.0 did: version 1 keys everywhere
	v1, _ := e2ee.Derive(user, password)
	if err := waitRateLimit(t, func() error { return api.Register(user, user+"@example.com", v1.AuthKey) }); err != nil {
		t.Fatal(err)
	}
	if err := waitRateLimit(t, func() error { _, err := api.Login(user, v1.AuthKey, ""); return err }); err != nil {
		t.Fatal(err)
	}
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalECPrivateKey(priv)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	signer, _ := ssh.ParsePrivateKey(pemBytes)
	pub := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
	if err := waitRateLimit(t, func() error { return api.RegisterKey(pub, v1.AuthKey) }); err != nil {
		t.Fatal(err)
	}
	storage, err := api.E2EEStorage()
	if err != nil {
		t.Fatal(err)
	}
	hkm := sshconn.NewHostKeyManager(t.TempDir())
	hkm.Load()
	connect := func() *Conn {
		t.Helper()
		c, err := Connect(ConnectParams{Storage: storage, PEM: pemBytes, HKM: hkm, Confirm: func(string, string) bool { return true }})
		if err != nil {
			t.Fatalf("connect: %v", err)
		}
		return c
	}
	c := connect()
	if _, err := Init(c, InitParams{API: api, Info: info, Keys: v1, ConsentEscrow: func(string) bool { return true }}); err != nil {
		t.Fatal(err)
	}
	plain := plainDir(t)
	if err := Unlock(c, v1, plain); err != nil {
		t.Fatal(err)
	}
	const secret = "written before the move"
	if err := os.WriteFile(filepath.Join(plain, "a.txt"), []byte(secret), 0o600); err != nil {
		t.Fatal(err)
	}
	e2ee.UnmountVolume(plain)
	c.Close()

	// 2. the new client signs in with both keys; the server still knows only the version 1 key
	ks, err := e2ee.DeriveSet(info.KdfSalt, user, password)
	if err != nil || ks.Version != 2 {
		t.Fatalf("%v %+v", err, ks)
	}
	api2 := apiclient.New(url, "", "")
	if err := waitRateLimit(t, func() error {
		_, err := api2.LoginKeys(user, ks.Current.AuthKey, ks.LegacyAuthKey(), "")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if v, err := api2.KdfVersion(); err != nil || v != 1 {
		t.Fatalf("account version before the move: %d %v", v, err)
	}

	// 3. unlocking moves the volume, the data is intact, and a second unlock has nothing to move
	c = connect()
	plain = plainDir(t)
	moved, err := UnlockSet(c, ks, plain)
	if err != nil || !moved {
		t.Fatalf("UnlockSet: moved=%v %v", moved, err)
	}
	if b, err := os.ReadFile(filepath.Join(plain, "a.txt")); err != nil || string(b) != secret {
		t.Fatalf("after the move: %q %v", b, err)
	}
	e2ee.UnmountVolume(plain)
	if _, err := os.Stat(c.confPath() + ".bak"); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("the version 1 config is still on the server: %v", err)
	}
	conf, _ := os.ReadFile(c.confPath())
	if _, err := e2ee.ReadMasterKey(conf, v1.VolumePassphrase); !errors.Is(err, e2ee.ErrWrongPassphrase) {
		t.Fatalf("the version 1 passphrase still opens the config: %v", err)
	}
	c.Close()
	c = connect()
	plain = plainDir(t)
	if moved, err := UnlockSet(c, ks, plain); err != nil || moved {
		t.Fatalf("second UnlockSet: moved=%v %v", moved, err)
	}
	e2ee.UnmountVolume(plain)
	c.Close()

	// 4. the login key moves; then only the version 2 key signs in, and an old client is refused
	if err := api2.UpgradeKdf(ks.Legacy.AuthKey, ks.Current.AuthKey, ""); err != nil {
		t.Fatal(err)
	}
	if v, err := api2.KdfVersion(); err != nil || v != 2 {
		t.Fatalf("account version after the move: %d %v", v, err)
	}
	old := apiclient.New(url, "", "")
	if err := waitRateLimit(t, func() error { _, err := old.Login(user, v1.AuthKey, ""); return err }); err == nil {
		t.Fatal("the version 1 login key still signs in")
	}
	if err := waitRateLimit(t, func() error {
		_, err := apiclient.New(url, "", "").LoginKeys(user, ks.Current.AuthKey, ks.LegacyAuthKey(), "")
		return err
	}); err != nil {
		t.Fatal(err)
	}
}
