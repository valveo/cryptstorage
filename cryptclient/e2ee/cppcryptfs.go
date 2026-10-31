package e2ee

import (
	"bytes"
	"context"
	"cryptclient/appdir"
	"cryptclient/nowindow"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// On Windows the volume is opened with cppcryptfs (https://github.com/bailey27/cppcryptfs), a
// gocryptfs-compatible implementation on top of the Dokan driver. CI proved both directions: it reads
// the gocryptfs.conf this client writes, and gocryptfs on Linux decrypts what it writes
// (.github/workflows/windows-spike.yml). It has no standard input for the password, so the password
// goes on the command line of cppcryptfsctl for the moment of mounting; it is the derived volume
// passphrase, not the user's own password (design-e2ee.md section 5a).

const (
	cppGUI = "cppcryptfs.exe"
	cppCtl = "cppcryptfsctl.exe"
)

// cppDirs are the places the two programs are looked for after PATH.
func cppDirs() []string {
	var dirs []string
	if d := os.Getenv("CRYPTCLIENT_CPPCRYPTFS_DIR"); d != "" {
		dirs = append(dirs, d)
	}
	for _, env := range []string{"ProgramFiles", "ProgramW6432", "LOCALAPPDATA"} {
		if base := os.Getenv(env); base != "" {
			dirs = append(dirs, filepath.Join(base, "cppcryptfs"),
				filepath.Join(base, "CryptStorage"), filepath.Join(base, appdir.Name), filepath.Join(base, appdir.Legacy))
		}
	}
	return dirs
}

func findProgram(name string) (string, error) {
	if p, err := exec.LookPath(name); err == nil {
		return p, nil
	}
	for _, d := range cppDirs() {
		p := filepath.Join(d, name)
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}
	return "", fmt.Errorf("%s is not installed", name)
}

// CppcryptfsInstalled reports whether both programs can be found (used by diagnose and setup).
func CppcryptfsInstalled() bool {
	_, e1 := findProgram(cppGUI)
	_, e2 := findProgram(cppCtl)
	return e1 == nil && e2 == nil
}

// runCtl runs cppcryptfsctl and returns its output with the NUL bytes of wide-character output removed.
func runCtl(args ...string) (string, error) {
	ctl, err := findProgram(cppCtl)
	if err != nil {
		return "", err
	}
	logf, err := os.CreateTemp("", "cppctl-log-")
	if err != nil {
		return "", err
	}
	defer os.Remove(logf.Name())
	defer logf.Close()
	// A hung cppcryptfs (for example one waiting behind an error dialog) must not hang the client.
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	cmd := nowindow.CommandContext(ctx, ctl, args...)
	cmd.Stdout, cmd.Stderr = logf, logf
	runErr := cmd.Run()
	if ctx.Err() != nil {
		runErr = errors.New("cppcryptfsctl did not answer in time")
	}
	raw, _ := os.ReadFile(logf.Name())
	return strings.TrimSpace(string(bytes.ReplaceAll(raw, []byte{0}, nil))), runErr
}

func cppAnswers() bool {
	out, err := runCtl("--list")
	return err == nil && !strings.Contains(out, "Unable to open pipe")
}

// ensureCppRunning makes sure the cppcryptfs process that cppcryptfsctl talks to is up. A previous
// instance may still be shutting down (it was told to exit after the last unmount); a new one started
// meanwhile would see it and quit, so the start is repeated.
func ensureCppRunning() error {
	if cppAnswers() {
		return nil
	}
	gui, err := findProgram(cppGUI)
	if err != nil {
		return err
	}
	for attempt := 0; attempt < 4; attempt++ {
		cmd := exec.Command(gui, "-t") // -t: start hidden in the system tray
		if err := cmd.Start(); err != nil {
			return err
		}
		nowindow.EndWithMe(cmd.Process.Pid) // a killed client must not leave a stale mount behind
		_ = cmd.Process.Release()
		deadline := time.Now().Add(8 * time.Second)
		for time.Now().Before(deadline) {
			if cppAnswers() {
				return nil
			}
			time.Sleep(500 * time.Millisecond)
		}
	}
	return errors.New("cppcryptfs did not start (is the Dokan driver installed?)")
}

func cppMount(cipherDir, plainDir, password, confPath string, readOnly bool) error {
	if err := ensureCppRunning(); err != nil {
		return err
	}
	args := []string{"--mount=" + cipherDir, "--drive=" + plainDir, "--password=" + password}
	if readOnly {
		args = append(args, "--readonly")
	}
	if confPath != "" {
		args = append(args, "--config="+confPath)
	}
	out, err := runCtl(args...)
	// Right after cppcryptfs starts, opening the config on a freshly connected network drive can fail once.
	// An instance that was told to exit a moment ago can still answer on the pipe and then vanish.
	for try := 0; try < 3 && err != nil; try++ {
		low := strings.ToLower(out)
		if !strings.Contains(low, "failed to open config") && !strings.Contains(low, "named pipe") {
			break
		}
		time.Sleep(3 * time.Second)
		if e := ensureCppRunning(); e != nil {
			return e
		}
		out, err = runCtl(args...)
	}
	if err != nil || strings.Contains(strings.ToLower(out), "password") {
		low := strings.ToLower(out)
		if strings.Contains(low, "password") && (strings.Contains(low, "incorrect") || strings.Contains(low, "wrong") || strings.Contains(low, "invalid")) {
			return ErrWrongPassphrase
		}
		if err != nil {
			return fmt.Errorf("cppcryptfs: %v: %s", err, out)
		}
	}
	return nil
}

// cppMountWithMasterKey mounts using the master key by wrapping it under a throw-away passphrase in a
// temporary config file; the volume's own gocryptfs.conf is not touched.
func cppMountWithMasterKey(cipherDir, plainDir string, masterKey []byte, readOnly bool) error {
	tmpPass := make([]byte, 16)
	if _, err := rand.Read(tmpPass); err != nil {
		return err
	}
	pass := fmt.Sprintf("%x", tmpPass)
	conf, err := MakeConf(masterKey, []byte(pass), 10)
	if err != nil {
		return err
	}
	dir, err := os.MkdirTemp("", "cryptstorage-conf-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	confPath := filepath.Join(dir, "gocryptfs.conf")
	if err := os.WriteFile(confPath, conf, 0o600); err != nil {
		return err
	}
	return cppMount(cipherDir, plainDir, pass, confPath, readOnly)
}

func cppUnmount(plainDir string) error {
	var last error
	for i := 0; i < 5; i++ {
		out, err := runCtl("--unmount=" + plainDir)
		if err == nil {
			_, _ = runCtl("--exit") // closes cppcryptfs when nothing else is mounted
			for j := 0; j < 20 && cppAnswers(); j++ {
				time.Sleep(500 * time.Millisecond) // wait until it has really gone, or is still serving other drives
			}
			return nil
		}
		last = fmt.Errorf("%v: %s", err, out)
		time.Sleep(time.Second)
	}
	return last
}

// DokanInstalled reports whether the Dokan 2 driver library that cppcryptfs loads is present.
func DokanInstalled() bool {
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = `C:\Windows`
	}
	_, err := os.Stat(filepath.Join(root, "System32", "dokan2.dll"))
	return err == nil
}
