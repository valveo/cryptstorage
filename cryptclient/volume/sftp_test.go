package volume

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"cryptclient/apiclient"
	"cryptclient/e2ee"
	"cryptclient/sshconn"
)

// The client's whole connection path without the API: SSHFS(-Win) to an SSH server that serves /data
// with the given key, a volume created on it, unlocked through gocryptfs (Linux) or cppcryptfs
// (Windows), a file written and the ciphertext inspected by the caller.
//
// The Windows CI job points it at a Linux sshd inside WSL on the runner (.github/workflows/windows.yml).
//
//	CRYPTSTORAGE_IT_SSH=127.0.0.1:2222:tester  CRYPTSTORAGE_IT_SSH_KEY=<PEM key file>
func TestSFTPVolume(t *testing.T) {
	target := os.Getenv("CRYPTSTORAGE_IT_SSH")
	keyFile := os.Getenv("CRYPTSTORAGE_IT_SSH_KEY")
	if target == "" || keyFile == "" {
		t.Skip("CRYPTSTORAGE_IT_SSH and CRYPTSTORAGE_IT_SSH_KEY not set")
	}
	parts := strings.Split(target, ":")
	if len(parts) != 3 {
		t.Fatalf("CRYPTSTORAGE_IT_SSH must be host:port:user, got %q", target)
	}
	host, user := parts[0], parts[2]
	port, _ := strconv.Atoi(parts[1])
	pemKey, err := os.ReadFile(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	stick := t.TempDir()
	hkm := sshconn.NewHostKeyManager(stick)
	_ = hkm.Load()
	conn, err := Connect(ConnectParams{
		Storage: &apiclient.E2EEStorage{SSHHost: host, SSHPort: port, SSHUser: user},
		PEM:     pemKey, HKM: hkm,
		Confirm: func(h, fp string) bool { return true },
	})
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Logf("ciphertext mounted at %s", conn.CipherDir)

	// plain file operations on the mounted ciphertext, to tell SSHFS problems from volume problems
	probe := filepath.Join(conn.CipherDir, "probe.txt")
	if err := os.WriteFile(probe, []byte("probe"), 0o600); err != nil {
		t.Errorf("plain write on the mounted storage: %v", err)
	} else if b, err := os.ReadFile(probe); err != nil || string(b) != "probe" {
		t.Errorf("plain read back: %q %v", b, err)
	}
	os.Remove(probe)

	keys := &e2ee.Keys{VolumePassphrase: []byte("derived-volume-passphrase")}
	mk, _ := e2ee.NewMasterKey()
	conf, err := e2ee.MakeConf(mk, keys.VolumePassphrase, 10)
	if err != nil {
		t.Fatal(err)
	}
	if err := e2ee.WriteVolumeFiles(conn.CipherDir, conf, make([]byte, 16)); err != nil {
		conn.Close()
		t.Fatalf("writing the volume files over SSHFS: %v", err)
	}

	plain := filepath.Join(t.TempDir(), "plain")
	if err := os.Mkdir(plain, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := Unlock(conn, keys, plain); err != nil {
		conn.Close()
		t.Fatalf("unlock: %v", err)
	}
	if err := os.WriteFile(filepath.Join(plain, "secret-name.txt"), []byte("hello"), 0o600); err != nil {
		t.Errorf("write: %v", err)
	}
	if err := e2ee.UnmountVolume(plain); err != nil {
		t.Errorf("unmount plain: %v", err)
	}
	if err := conn.Close(); err != nil {
		t.Errorf("close connection: %v", err)
	}

	// What the server holds is checked by the caller (the CI job lists /data on the server afterwards).
}
