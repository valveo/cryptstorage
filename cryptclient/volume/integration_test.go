package volume

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
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
	"cryptclient/escrowcheck"
	"cryptclient/sshconn"
)

// Runs the whole flow against a real API, sshd, sshfs and gocryptfs: scripts/e2ee_integration.sh.
// CRYPTSTORAGE_IT_URL is the API; CRYPTSTORAGE_IT_CIPHER_BASE is the server's chroot base (to look at the ciphertext).

func TestIntegration(t *testing.T) {
	url := os.Getenv("CRYPTSTORAGE_IT_URL")
	if url == "" {
		t.Skip("CRYPTSTORAGE_IT_URL not set")
	}
	base := os.Getenv("CRYPTSTORAGE_IT_CIPHER_BASE")
	api := apiclient.New(url, "", "")
	info, err := api.ServerInfo()
	if err != nil || info.StorageMode != "e2ee" {
		t.Fatalf("server info: %v %+v", err, info)
	}

	user := fmt.Sprintf("it%d%d", os.Getpid(), time.Now().Unix()%100000)
	keys, _ := e2ee.Derive(user, "correct horse battery staple")
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
	pub := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
	if err := api.RegisterKey(pub, keys.AuthKey); err != nil {
		t.Fatal(err)
	}
	storage, err := api.E2EEStorage()
	if err != nil {
		t.Fatal(err)
	}
	if len(storage.SSHHostKeys) == 0 {
		t.Fatal("the API did not list the SFTP host keys (SFTP_HOST_KEY_FILES)")
	}
	hkm := sshconn.NewHostKeyManager(t.TempDir())
	hkm.Load()
	connect := func() *Conn {
		t.Helper()
		// the API lists the SFTP host key, so the user must never be asked about it
		confirm := func(string, string) bool {
			if len(storage.SSHHostKeys) > 0 {
				t.Error("asked to trust a host key that the API listed")
			}
			return true
		}
		c, err := Connect(ConnectParams{Storage: storage, PEM: pemBytes, HKM: hkm, Confirm: confirm})
		if err != nil {
			t.Fatalf("connect: %v", err)
		}
		return c
	}
	unlockAndRead := func(k *e2ee.Keys, write string) (string, error) {
		c := connect()
		defer c.Close()
		plain := plainDir(t)
		if err := Unlock(c, k, plain); err != nil {
			return "", err
		}
		defer e2ee.UnmountVolume(plain)
		f := filepath.Join(plain, "secret-name.txt")
		if write != "" {
			if err := os.WriteFile(f, []byte(write), 0o600); err != nil {
				return "", err
			}
		}
		b, err := os.ReadFile(f)
		return string(b), err
	}

	// 1. create the volume
	c := connect()
	asked := ""
	consent := func(fp string) bool { asked = fp; return true }
	res, err := Init(c, InitParams{API: api, Info: info, Keys: keys, ConsentEscrow: consent})
	if err != nil {
		t.Fatal(err)
	}
	if res.RecoveryCode == "" || !res.Escrow {
		t.Fatalf("policy 'both' should give a code and an escrow copy: %+v", res)
	}
	if want, _ := escrowcheck.Fingerprint(*info.EscrowPublicKey); asked != want {
		t.Fatalf("consent was asked for key %q, want %q", asked, want)
	}
	if _, err := Init(c, InitParams{API: api, Info: info, Keys: keys}); err == nil {
		t.Fatal("a second Init must refuse")
	}
	c.Close()

	// 2. use it, and look at what the server holds
	const secret = "top secret plaintext 4711"
	if got, err := unlockAndRead(keys, secret); err != nil || got != secret {
		t.Fatalf("write/read: %q %v", got, err)
	}
	if base != "" {
		dir := filepath.Join(base, storage.SSHUser, "data")
		n := 0
		filepath.Walk(dir, func(p string, fi os.FileInfo, err error) error {
			if err != nil || fi.IsDir() {
				return nil
			}
			n++
			b, _ := os.ReadFile(p)
			if strings.Contains(string(b), secret) || strings.Contains(filepath.Base(p), "secret-name") {
				t.Errorf("the server can see plaintext in %s", p)
			}
			return nil
		})
		if n < 3 {
			t.Errorf("expected conf, diriv and an encrypted file, found %d files", n)
		}
	}

	// 3. a wrong password does not open it
	wrong, _ := e2ee.Derive(user, "not the right password")
	if _, err := unlockAndRead(wrong, ""); err == nil {
		t.Fatal("wrong password opened the volume")
	}

	// 4. recovery: forgotten password, only the recovery code. The user has deleted the volume's check
	// file (it is visible in the volume's root); recovery must still tell the right key from a wrong one.
	c = connect()
	plain := plainDir(t)
	if err := Unlock(c, keys, plain); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(plain, e2ee.CanaryName)); err != nil {
		t.Fatal(err)
	}
	e2ee.UnmountVolume(plain)
	c.Close()
	mk, err := e2ee.ParseRecoveryCode(res.RecoveryCode)
	if err != nil {
		t.Fatal(err)
	}
	proof, _ := e2ee.RecoveryProof(mk)
	newKeys, _ := e2ee.Derive(user, "a brand new password phrase")
	api2 := apiclient.New(url, "", "")
	if err := api2.RecoverE2EE(user, strings.Repeat("0", 64), newKeys.AuthKey, ""); err == nil {
		t.Fatal("a wrong proof must be refused")
	}
	if err := api2.RecoverE2EE(user, proof, newKeys.AuthKey, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := api2.Login(user, keys.AuthKey, ""); err == nil {
		t.Fatal("the old login key must be dead")
	}
	if _, err := api2.Login(user, newKeys.AuthKey, ""); err != nil {
		t.Fatal(err)
	}
	c = connect()
	badMK := make([]byte, 32)
	if _, err := Recover(c, badMK, newKeys.VolumePassphrase); err == nil {
		t.Fatal("a wrong master key must not be accepted (gocryptfs would not notice)")
	}
	if _, err := Recover(c, mk, newKeys.VolumePassphrase); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(c.confPath() + ".bak"); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("the previous config is still on the server after recovery: %v", err)
	}
	c.Close()
	if got, err := unlockAndRead(newKeys, ""); err != nil || got != secret {
		t.Fatalf("after recovery: %q %v", got, err)
	}
	c = connect()
	plain = plainDir(t)
	if err := Unlock(c, newKeys, plain); err != nil {
		t.Fatal(err)
	}
	if err := e2ee.CheckCanary(plain); err != nil {
		t.Errorf("the check file was not put back: %v", err)
	}
	e2ee.UnmountVolume(plain)
	c.Close()
	if _, err := unlockAndRead(keys, ""); err == nil {
		t.Fatal("the old passphrase must no longer work")
	}

	// 5. password change
	third, _ := e2ee.Derive(user, "yet another long password")
	c = connect()
	restore, err := Rewrap(c, newKeys.VolumePassphrase, third.VolumePassphrase)
	if err != nil {
		t.Fatal(err)
	}
	_ = restore
	// The previous config stays until the change is done (change-password drops it after the server has
	// the new login key); the next Unlock removes one that was left behind
	if _, err := os.Stat(c.confPath() + ".bak"); err != nil {
		t.Fatalf("Rewrap kept no previous config: %v", err)
	}
	c.Close()
	if got, err := unlockAndRead(third, ""); err != nil || got != secret {
		t.Fatalf("after rewrap: %q %v", got, err)
	}
	c = connect()
	if _, err := os.Stat(c.confPath() + ".bak"); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("Unlock left the previous config on the server: %v", err)
	}
	c.Close()

	// 6. the sealed copy opens for the operator and matches the user's code
	blobPath := os.Getenv("CRYPTSTORAGE_IT_BLOB_OUT")
	if blobPath != "" {
		os.WriteFile(blobPath, []byte(hex.EncodeToString(mk)+"\n"+res.RecoveryCode+"\n"+user+"\n"), 0o600)
	}
}
