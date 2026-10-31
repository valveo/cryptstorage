package sshconn

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"time"

	"golang.org/x/crypto/ssh"
)

// Config holds connection parameters.
type Config struct {
	Host           string
	Port           int
	Username       string
	PrivateKey     []byte // PEM bytes, decrypted
	MountPoint     string // local directory to mount into
	HostKeyManager *HostKeyManager
}

// TestConnection verifies the SSH connection works before mounting.
func TestConnection(cfg Config, confirmFn func(hostname, fingerprint string) bool) error {
	signer, err := ssh.ParsePrivateKey(cfg.PrivateKey)
	if err != nil {
		return fmt.Errorf("parsing private key: %w", err)
	}

	hkCallback := cfg.HostKeyManager.GetCallback(confirmFn)

	sshCfg := &ssh.ClientConfig{
		User:            cfg.Username,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: hkCallback,
		Timeout:         10 * time.Second,
	}

	addr := net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port))
	client, err := ssh.Dial("tcp", addr, sshCfg)
	if err != nil {
		return fmt.Errorf("connecting to %s: %w", addr, err)
	}
	client.Close()
	return nil
}

// Session holds what has to stay alive while the storage is mounted: the in-process
// agent with the key and the pinned known_hosts file. sshfs reconnects on its own
// (-o reconnect) and needs both again every time; Close removes them.
type Session struct {
	agent      *Agent
	knownHosts string
	win        *winMount // Windows: the sshfs process that serves the drive
}

// Dir is where the server's storage is mounted. On Windows the drive letter is chosen by Mount,
// so this is the only place that knows it (for example "X:\").
func (s *Session) Dir() string {
	if s != nil && s.win != nil {
		return s.win.drive + `\`
	}
	return ""
}

// Unmount disconnects the storage: stops the sshfs process on Windows, runs the unmount tool elsewhere.
func (s *Session) Unmount(mountPoint string) error {
	if s != nil && s.win != nil {
		return s.win.stop()
	}
	return Umount(mountPoint)
}

// Close drops the key and removes the temporary files. Safe to call more than once.
func (s *Session) Close() {
	if s == nil {
		return
	}
	if s.agent != nil {
		s.agent.Close()
		s.agent = nil
	}
	if s.knownHosts != "" {
		secureDelete(s.knownHosts)
		s.knownHosts = ""
	}
}

// Mount mounts the remote /data directory using SSHFS and returns the Session that must
// be kept open (and closed after unmounting).
// Uses the pinned host key via a temporary known_hosts file.
func Mount(cfg Config) (*Session, error) {
	knownHostsFile, err := writeKnownHosts(cfg.Host, cfg.Port, cfg.HostKeyManager)
	if err != nil {
		return nil, fmt.Errorf("writing known_hosts: %w", err)
	}
	sess := &Session{knownHosts: knownHostsFile}

	addr := fmt.Sprintf("%s@%s:/data", cfg.Username, cfg.Host)
	port := strconv.Itoa(cfg.Port)

	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "linux", "darwin":
		// The key lives in an in-process agent, never in a file
		ag, err := StartAgent(cfg.PrivateKey)
		if err != nil {
			sess.Close()
			return nil, err
		}
		sess.agent = ag
		cmd = exec.Command("sshfs", sshfsArgs(addr, cfg.MountPoint, port, ag.Socket(), "", knownHostsFile, true)...)

	case "windows":
		// sshfs-win cannot talk to a Unix-socket agent: fall back to a key file that is
		// deleted as soon as the drive is up (no automatic reconnect on this platform)
		keyFile, err := writeTempKey(cfg.PrivateKey)
		if err != nil {
			sess.Close()
			return nil, err
		}
		defer secureDelete(keyFile)
		w, err := mountWindows(addr, cfg.MountPoint, port, keyFile, knownHostsFile)
		if err != nil {
			sess.Close()
			return nil, err
		}
		sess.win = w
		return sess, nil

	default:
		sess.Close()
		return nil, fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}

	if out, err := cmd.CombinedOutput(); err != nil {
		sess.Close()
		return nil, fmt.Errorf("sshfs failed: %w\n%s", err, out)
	}
	return sess, nil
}

// sshfsArgs builds the sshfs command line. Exactly one of agentSocket / keyFile is set.
func sshfsArgs(addr, mountPoint, port, agentSocket, keyFile, knownHosts string, reconnect bool) []string {
	args := []string{addr, mountPoint, "-p", port}
	if agentSocket != "" {
		args = append(args, "-o", "IdentityAgent="+agentSocket)
	}
	if keyFile != "" {
		args = append(args, "-o", "IdentityFile="+keyFile)
	}
	args = append(args,
		"-o", "UserKnownHostsFile="+knownHosts,
		"-o", "StrictHostKeyChecking=yes",
		"-o", "PasswordAuthentication=no",
	)
	if reconnect {
		args = append(args, "-o", "reconnect", "-o", "ServerAliveInterval=15")
	}
	if runtime.GOOS == "linux" {
		// No directory cache: another device's changes must show at once, otherwise the synchronised
		// folder can miss them or overwrite a change it has not seen (docs/design-features.md 5.1)
		args = append(args, "-o", "dir_cache=no")
	}
	return args
}

// Umount unmounts the SSHFS mount point.
func Umount(mountPoint string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "linux":
		cmd = exec.Command("fusermount", "-u", mountPoint)
	case "darwin":
		cmd = exec.Command("umount", mountPoint)
	case "windows":
		return errors.New("on Windows the connection is closed through its session")
	default:
		return fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}

	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("umount failed: %w\n%s", err, out)
	}
	return nil
}

// writeKnownHosts writes a temporary known_hosts file based on the host key
// stored on the stick, for sshfs.
func writeKnownHosts(host string, port int, hkm *HostKeyManager) (string, error) {
	stored, ok := hkm.stored[normalizeHost(host)]
	if !ok {
		return "", fmt.Errorf("no stored host key for %s – connect once first to pin the key", host)
	}
	if stored.PublicKey == "" {
		return "", fmt.Errorf("stored host key for %s is in an old format – delete %s from the USB stick and connect again", host, HostKeyFile)
	}

	// known_hosts format: "<host> <keytype> <base64 public key>"; a non-default
	// port is written as "[host]:port".
	entry := host
	if port != 22 {
		entry = fmt.Sprintf("[%s]:%d", host, port)
	}
	line := fmt.Sprintf("%s %s %s\n", entry, stored.KeyType, stored.PublicKey)
	f, err := os.CreateTemp("", "known_hosts-*")
	if err != nil {
		return "", err
	}
	defer f.Close()
	if _, err := f.WriteString(line); err != nil {
		os.Remove(f.Name())
		return "", err
	}
	return f.Name(), nil
}
