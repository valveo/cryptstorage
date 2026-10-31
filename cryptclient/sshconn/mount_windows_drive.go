package sshconn

import (
	"cryptclient/nowindow"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

var mountSeq atomic.Int64

// errUntrustedMountPoint is Windows' ERROR_UNTRUSTED_MOUNT_POINT (448).
const errUntrustedMountPoint = syscall.Errno(448)

// winMount is one SSHFS-Win mount: the sshfs.exe process runs in the foreground (-f) as our child
// and serves a drive letter for as long as it lives. Stopping the process unmounts the drive.
type winMount struct {
	drive string // "X:"
	cmd   *exec.Cmd
	done  chan struct{}
	log   string
}

func sshfsExe() (string, error) {
	if p, err := exec.LookPath("sshfs"); err == nil {
		return p, nil
	}
	for _, env := range []string{"ProgramFiles", "ProgramW6432"} {
		if base := os.Getenv(env); base != "" {
			p := filepath.Join(base, "SSHFS-Win", "bin", "sshfs.exe")
			if _, err := os.Stat(p); err == nil {
				return p, nil
			}
		}
	}
	return "", errors.New("SSHFS-Win is not installed (run: cryptclient install-deps)")
}

func freeDriveLetter() (string, error) {
	for l := 'Z'; l >= 'F'; l-- {
		d := string(l) + ":"
		if _, err := os.Stat(d + `\`); err != nil {
			return d, nil
		}
	}
	return "", errors.New("no free drive letter")
}

// mountWindows starts sshfs.exe and waits until the mount answers. mountPoint "" mounts at a new directory
// under the temp folder (WinFsp creates it): the ciphertext is only for cppcryptfs, and a drive letter would
// show it to the user in Explorer next to the real storage. If Windows refuses the directory, a free drive
// letter is used.
func mountWindows(addr, mountPoint, port, keyFile, knownHosts string) (*winMount, error) {
	if mountPoint != "" {
		return mountWindowsAt(addr, mountPoint, port, keyFile, knownHosts)
	}
	dir := filepath.Join(os.TempDir(), fmt.Sprintf("cryptstorage-mnt-%d-%d", os.Getpid(), mountSeq.Add(1)))
	w, err := mountWindowsAt(addr, dir, port, keyFile, knownHosts)
	if err == nil {
		return w, nil
	}
	// said, not hidden: support needs to know why the ciphertext shows up as a drive
	fmt.Fprintf(os.Stderr, "Note: the server connection could not use the folder %s (%v); using a drive letter.\n", dir, err)
	letter, err2 := freeDriveLetter()
	if err2 == nil {
		var w2 *winMount
		if w2, err2 = mountWindowsAt(addr, letter, port, keyFile, knownHosts); err2 == nil {
			return w2, nil
		}
	}
	return nil, fmt.Errorf("directory %s: %v; drive letter: %v", dir, err, err2)
}

func mountWindowsAt(addr, drive, port, keyFile, knownHosts string) (*winMount, error) {
	exe, err := sshfsExe()
	if err != nil {
		return nil, err
	}
	// the cygwin-based sshfs reads Windows paths with forward slashes
	slash := func(p string) string { return strings.ReplaceAll(p, `\`, "/") }
	// Each mount is named after this process and a counter, so the wait below can tell its own drive from
	// one that another process mounted at the same letter a moment earlier (two clients started at once).
	volname := fmt.Sprintf("cryptstorage-%d-%d", os.Getpid(), mountSeq.Add(1))
	// a folder goes to WinFsp-FUSE through Cygwin, which calls a path with backslashes "invalid mount point"
	args := []string{addr, slash(drive), "-f", "-p", port,
		"-o", "IdentityFile=" + slash(keyFile),
		"-o", "UserKnownHostsFile=" + slash(knownHosts),
		"-o", "StrictHostKeyChecking=yes",
		"-o", "PasswordAuthentication=no",
		// the options SSHFS-Win's own service uses: files belong to the signed-in user, nobody else gets access
		"-o", "idmap=user,uid=-1,gid=-1,umask=0007,create_umask=0007",
		"-o", "fstypename=SSHFS",
		"-o", "volname=" + volname,
		// No cache (sshfs 2.x, as in SSHFS-Win): another device's changes must show at once, as with
		// dir_cache=no on Linux (docs/design-features.md 5.1)
		"-o", "cache=no",
		// nor in WinFsp's FUSE layer above it: a mount at a folder kept showing another device's files late
		"-o", "FileInfoTimeout=0", "-o", "DirInfoTimeout=0",
	}
	if os.Getenv("CRYPTCLIENT_SSHFS_DEBUG") == "1" { // for support and CI: shows why a connection failed
		args = append(args, "-o", "sshfs_debug", "-o", "LogLevel=DEBUG1")
	}
	logf, err := os.CreateTemp("", "sshfs-log-")
	if err != nil {
		return nil, err
	}
	cmd := exec.Command(exe, args...)
	// sshfs starts "ssh" from PATH. Windows' own OpenSSH there cannot use the pipe sshfs gives it and
	// quits at once ("Connection reset by peer"), so the ssh that comes with SSHFS-Win must come first.
	cmd.Env = append(os.Environ(), "PATH="+filepath.Dir(exe)+string(os.PathListSeparator)+os.Getenv("PATH"))
	// A console of its own (hidden): the Cygwin runtime changes the mode of the console it is attached to,
	// and in ours every later line then started where the previous one ended (runs of spaces).
	nowindow.Hide(cmd)
	// Cygwin programs misbehave when their standard handles are NUL or plain files (the ssh that sshfs
	// starts sees an immediately closed input and quits: "Connection reset by peer"), so they get
	// real pipes, as the WinFsp launcher gives them. Output is copied to the log file.
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	pr, pw := io.Pipe()
	cmd.Stdout, cmd.Stderr = pw, pw
	go io.Copy(logf, pr)
	if err := cmd.Start(); err != nil {
		logf.Close()
		os.Remove(logf.Name())
		return nil, err
	}
	nowindow.EndWithMe(cmd.Process.Pid) // and the ssh it starts: they end with the client
	_ = stdin                           // kept open for the lifetime of the process
	w := &winMount{drive: drive, cmd: cmd, done: make(chan struct{}), log: logf.Name()}
	go func() { cmd.Wait(); pw.Close(); stdin.Close(); close(w.done) }()

	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case <-w.done:
			lines := 8
			if os.Getenv("CRYPTCLIENT_SSHFS_DEBUG") == "1" {
				lines = 40
			}
			out, _ := os.ReadFile(w.log)
			os.Remove(w.log)
			return nil, fmt.Errorf("sshfs stopped before the drive appeared: %s", lastLines(string(out), lines))
		default:
		}
		_, err := os.Stat(drive + `\`)
		if err == nil {
			if label, ok := volumeLabel(drive + `\`); !ok || label == volname {
				return w, nil
			}
			// another mount holds this letter: ours fails and ends, which the select above reports
		}
		// The folder mount is up but Windows will not let this program through it (RedirectionGuard,
		// Windows 11 26200): no use waiting the 30 seconds, the caller takes a drive letter instead
		if errors.Is(err, errUntrustedMountPoint) {
			w.stop()
			return nil, err
		}
		time.Sleep(300 * time.Millisecond)
	}
	w.stop()
	return nil, errors.New("the server connection did not come up in 30 seconds")
}

func lastLines(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(strings.ReplaceAll(s, "\r", "")), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

// stop ends the sshfs process (and the ssh it started) and waits for the drive to go away.
func (w *winMount) stop() error {
	if w == nil || w.cmd == nil || w.cmd.Process == nil {
		return nil
	}
	_ = nowindow.Command("taskkill", "/T", "/F", "/PID", strconv.Itoa(w.cmd.Process.Pid)).Run()
	select {
	case <-w.done:
	case <-time.After(10 * time.Second):
		return errors.New("sshfs did not stop")
	}
	os.Remove(w.log)
	for i := 0; i < 20; i++ {
		if _, err := os.Stat(w.drive + `\`); err != nil {
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	return errors.New("the drive " + w.drive + " is still there after disconnecting")
}
