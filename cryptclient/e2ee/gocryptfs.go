package e2ee

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// CanaryName is a small file written at setup. gocryptfs cannot tell a wrong master key from the
// right one on its own (design-e2ee.md F6), so recovery reads this file before changing anything.
const (
	// the earlier product name (secdisk) stays: existing volumes have this file
	CanaryName    = ".secdisk-canary"
	canaryContent = "secdisk-canary-v1\n"
)

func gocryptfsBin() (string, error) {
	p, err := exec.LookPath("gocryptfs")
	if err != nil {
		return "", errors.New("gocryptfs is not installed")
	}
	return p, nil
}

// MountVolume mounts the ciphertext directory at plainDir. The passphrase goes to gocryptfs
// through its standard input, never through a file or the command line.
func MountVolume(cipherDir, plainDir string, passphrase []byte) error {
	if runtime.GOOS == "windows" {
		return cppMount(cipherDir, plainDir, string(passphrase), "", false)
	}
	return runMount([]string{"-q", "-nosyslog", "-noprealloc", cipherDir, plainDir}, append(append([]byte{}, passphrase...), '\n'))
}

// MountVolumeWithMasterKey is for recovery. readOnly should be true for the check before any change.
func MountVolumeWithMasterKey(cipherDir, plainDir string, masterKey []byte, readOnly bool) error {
	if runtime.GOOS == "windows" {
		return cppMountWithMasterKey(cipherDir, plainDir, masterKey, readOnly)
	}
	args := []string{"-q", "-nosyslog", "-noprealloc", "-masterkey=stdin"}
	if readOnly {
		args = append(args, "-ro")
	}
	args = append(args, cipherDir, plainDir)
	return runMount(args, []byte(fmt.Sprintf("%x\n", masterKey)))
}

func runMount(args []string, stdin []byte) error {
	bin, err := gocryptfsBin()
	if err != nil {
		return err
	}
	// gocryptfs detaches into the background after mounting and keeps the inherited stdout and
	// stderr open. CombinedOutput would wait for those pipes to close - that is, until unmount.
	// Files do not need draining, so Run returns when the foreground process exits.
	logf, err := os.CreateTemp("", "gocryptfs-log-")
	if err != nil {
		return err
	}
	defer os.Remove(logf.Name())
	defer logf.Close()
	cmd := exec.Command(bin, args...)
	cmd.Stdin = bytes.NewReader(stdin)
	cmd.Stdout, cmd.Stderr = logf, logf
	if err := cmd.Run(); err != nil {
		out, _ := os.ReadFile(logf.Name())
		msg := strings.TrimSpace(string(out))
		if strings.Contains(msg, "Password incorrect") {
			return ErrWrongPassphrase
		}
		return fmt.Errorf("gocryptfs: %v: %s", err, msg)
	}
	return nil
}

// UnmountVolume unmounts plainDir, retrying briefly while files are still closing.
func UnmountVolume(plainDir string) error {
	if runtime.GOOS == "windows" {
		return cppUnmount(plainDir)
	}
	var cmd func() *exec.Cmd
	switch runtime.GOOS {
	case "linux":
		cmd = func() *exec.Cmd { return exec.Command("fusermount", "-u", plainDir) }
	case "darwin":
		cmd = func() *exec.Cmd { return exec.Command("umount", plainDir) }
	default:
		return errors.New("unsupported OS")
	}
	var last error
	for i := 0; i < 5; i++ {
		if out, err := cmd().CombinedOutput(); err == nil {
			return nil
		} else {
			last = fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
		}
		time.Sleep(time.Second)
	}
	return last
}

// WriteCanary creates the canary file in a mounted volume.
func WriteCanary(plainDir string) error {
	return os.WriteFile(filepath.Join(plainDir, CanaryName), []byte(canaryContent), 0o600)
}

// CheckCanary reports whether the mounted volume decrypts correctly. A missing check file gives an
// error that matches fs.ErrNotExist; VerifyKey then looks at the other files.
func CheckCanary(plainDir string) error {
	b, err := os.ReadFile(filepath.Join(plainDir, CanaryName))
	if err != nil {
		return fmt.Errorf("the check file could not be read, so this is not the right key: %w", err)
	}
	if string(b) != canaryContent {
		return errors.New("the check file has the wrong content")
	}
	return nil
}

// VerifyKey reports whether the volume mounted at plainDir (ciphertext in cipherDir) opened with the
// right key. It reads the check file; gocryptfs itself cannot tell a wrong master key (design-e2ee F6).
// The check file lives in the volume's root, where the user can see and delete it. Unlock writes it again
// when it is missing, but a recovery may come first, so a missing check file is not the end: any non-empty
// file that reads back proves the key, because gocryptfs authenticates every block (AES-GCM). With a wrong
// key no name decrypts, so the volume looks empty although the ciphertext has entries, and that is refused.
// A volume whose ciphertext holds nothing but its config has no data a wrong key could lose.
func VerifyKey(cipherDir, plainDir string) error {
	err := CheckCanary(plainDir)
	if err == nil || !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if !hasCipherEntries(cipherDir) {
		return nil
	}
	if readsAnyFile(plainDir, 2000) {
		return nil
	}
	return errors.New("the check file is missing and no file in the volume could be read, so this is not the right key")
}

// hasCipherEntries tells whether the ciphertext directory holds anything besides the volume's own files.
// Encrypted names are base64url and never start with a dot.
func hasCipherEntries(cipherDir string) bool {
	entries, err := os.ReadDir(cipherDir)
	if err != nil {
		return true // cannot tell: do not treat it as empty
	}
	for _, e := range entries {
		n := e.Name()
		if strings.HasPrefix(n, ".") || n == "gocryptfs.diriv" || strings.HasPrefix(n, "gocryptfs.conf") {
			continue
		}
		return true
	}
	return false
}

// readsAnyFile looks at up to limit entries under dir for a non-empty regular file whose first bytes read
// back without an error. The top level is listed with ReadDir: on Windows the mount point is a reparse
// point, which WalkDir reports as an irregular file and does not descend into.
func readsAnyFile(dir string, limit int) bool {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false
	}
	found, seen := false, 0
	stop := errors.New("stop")
	visit := func(p string, d fs.DirEntry, err error) error {
		if seen++; seen > limit {
			return stop
		}
		if err != nil || !d.Type().IsRegular() {
			return nil
		}
		if readsBack(p) {
			found = true
			return stop
		}
		return nil
	}
	for _, e := range entries {
		p := filepath.Join(dir, e.Name())
		if e.IsDir() {
			if filepath.WalkDir(p, visit) == stop {
				break
			}
		} else if visit(p, e, nil) == stop {
			break
		}
	}
	return found
}

func readsBack(p string) bool {
	f, err := os.Open(p)
	if err != nil {
		return false
	}
	defer f.Close()
	buf := make([]byte, 4096)
	n, err := f.Read(buf)
	return n > 0 && (err == nil || err == io.EOF)
}

// WriteVolumeFiles creates gocryptfs.conf and gocryptfs.diriv in an empty ciphertext directory.
func WriteVolumeFiles(cipherDir string, conf []byte, diriv []byte) error {
	confPath := filepath.Join(cipherDir, "gocryptfs.conf")
	if _, err := os.Stat(confPath); err == nil {
		return errors.New("a volume already exists here; refusing to overwrite it")
	}
	if err := os.WriteFile(filepath.Join(cipherDir, "gocryptfs.diriv"), diriv, 0o600); err != nil {
		return err
	}
	return os.WriteFile(confPath, conf, 0o600)
}
