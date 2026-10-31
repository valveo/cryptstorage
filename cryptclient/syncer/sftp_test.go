package syncer

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"cryptclient/apiclient"
	"cryptclient/deps"
	"cryptclient/e2ee"
	"cryptclient/sshconn"
	"cryptclient/volume"
)

// TestSFTPSync is the synchronised folder on the Windows route without the API: two devices, each with
// its own SSHFS-Win connection and cppcryptfs drive, synchronise one volume on a plain sshd (the
// `connection` job in .github/workflows/windows.yml). The server lock is replaced by an in-process one;
// the API lock itself is covered by TestIntegrationSync.
func TestSFTPSync(t *testing.T) {
	target := os.Getenv("CRYPTSTORAGE_IT_SSH")
	keyFile := os.Getenv("CRYPTSTORAGE_IT_SSH_KEY")
	if target == "" || keyFile == "" {
		t.Skip("CRYPTSTORAGE_IT_SSH and CRYPTSTORAGE_IT_SSH_KEY not set")
	}
	parts := strings.Split(target, ":")
	if len(parts) != 3 {
		t.Fatalf("CRYPTSTORAGE_IT_SSH must be host:port:user, got %q", target)
	}
	port, _ := strconv.Atoi(parts[1])
	storage := &apiclient.E2EEStorage{SSHHost: parts[0], SSHPort: port, SSHUser: parts[2]}
	pemKey, err := os.ReadFile(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	rclone := os.Getenv("CRYPTCLIENT_TEST_RCLONE")
	if rclone == "" {
		if rclone, err = deps.RclonePath(); errors.Is(err, deps.ErrNoRclone) {
			rclone, err = deps.InstallRclone(t.Logf)
		}
		if err != nil {
			t.Fatal(err)
		}
	}

	hkm := sshconn.NewHostKeyManager(t.TempDir())
	_ = hkm.Load()
	// A folder of its own on the server, so the volume of TestSFTPVolume (same account) stays as it is
	sub := "sync-test-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	connect := func() *volume.Conn {
		c, err := volume.Connect(volume.ConnectParams{Storage: storage, PEM: pemKey, HKM: hkm,
			Confirm: func(string, string) bool { return true }})
		if err != nil {
			t.Fatalf("connect: %v", err)
		}
		base := c.CipherDir
		if len(base) == 2 && base[1] == ':' {
			base += `\` // a drive letter alone means the current directory on that drive
		}
		c.CipherDir = filepath.Join(base, sub)
		return c
	}
	keys := &e2ee.Keys{VolumePassphrase: []byte("derived-volume-passphrase")}
	mk, _ := e2ee.NewMasterKey()
	conf, err := e2ee.MakeConf(mk, keys.VolumePassphrase, 10)
	if err != nil {
		t.Fatal(err)
	}
	first := connect()
	if err := os.Mkdir(first.CipherDir, 0o700); err != nil {
		first.Close()
		t.Fatal(err)
	}
	if err := e2ee.WriteVolumeFiles(first.CipherDir, conf, make([]byte, 16)); err != nil {
		first.Close()
		t.Fatalf("writing the volume files: %v", err)
	}

	dir := t.TempDir()
	lock := &fakeLock{ttl: 30 * time.Second}
	used := map[string]bool{}
	device := func(name string, conn *volume.Conn) *Syncer {
		plain := mountPoint(t, dir, name, used)
		if err := volume.Unlock(conn, keys, plain); err != nil {
			conn.Close()
			t.Fatalf("unlock for %s: %v", name, err)
		}
		t.Cleanup(func() { e2ee.UnmountVolume(plain); conn.Close() })
		t.Logf("%s: volume at %s", name, plain)
		return New(Config{Rclone: rclone, Local: filepath.Join(dir, name), Remote: plain,
			WorkDir: filepath.Join(dir, name+"-work"), Holder: name + "-0123456789abcdef", HolderName: name,
			Interval: time.Second, Log: t.Logf}, lock)
	}
	checkTwoDevices(t, device("laptop", first), device("desktop", connect()))
}

// mountPoint is where a device's volume opens: a free drive letter on Windows, as the client uses.
func mountPoint(t *testing.T, dir, name string, used map[string]bool) string {
	if runtime.GOOS != "windows" {
		p := filepath.Join(dir, name+"-volume")
		os.MkdirAll(p, 0o700)
		return p
	}
	for l := 'S'; l <= 'Z'; l++ {
		d := string(l) + ":"
		if _, err := os.Stat(d + `\`); err != nil && !used[d] {
			used[d] = true
			return d
		}
	}
	t.Fatal("no free drive letter between S: and Z:")
	return ""
}
