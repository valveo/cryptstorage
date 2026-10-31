// Package volume runs the end-to-end encrypted storage flows: connect to the server's ciphertext
// over SSHFS, create a volume, unlock it, change the passphrase and recover. The interactive
// commands in package main only ask questions and call these functions.
package volume

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"

	"cryptclient/apiclient"
	"cryptclient/e2ee"
	"cryptclient/escrowcheck"
	"cryptclient/sshconn"
)

// Conn is the SSHFS mount of the user's ciphertext directory on the server.
type Conn struct {
	CipherDir string
	sess      *sshconn.Session
	tmp       string // the mount point (a temporary directory, or the drive letter on Windows)
	ownsDir   bool   // tmp is a directory we created and must remove
}

// ConnectParams describes where and how to connect.
type ConnectParams struct {
	Storage *apiclient.E2EEStorage
	PEM     []byte // decrypted SSH private key
	HKM     *sshconn.HostKeyManager
	Confirm func(hostname, fingerprint string) bool
}

// Connect mounts the ciphertext directory in a private temporary directory.
func Connect(p ConnectParams) (*Conn, error) {
	// Windows mounts a drive letter that Mount picks; elsewhere a private temporary directory.
	tmp, ownsDir := "", false
	if runtime.GOOS != "windows" {
		var err error
		if tmp, err = os.MkdirTemp("", "cryptstorage-cipher-"); err != nil {
			return nil, err
		}
		ownsDir = true
	}
	cleanup := func() {
		if ownsDir {
			os.Remove(tmp)
		}
	}
	if err := p.HKM.Vouch(p.Storage.SSHHostKeys); err != nil {
		cleanup()
		return nil, err
	}
	cfg := sshconn.Config{
		Host: p.Storage.SSHHost, Port: p.Storage.SSHPort, Username: p.Storage.SSHUser,
		PrivateKey: p.PEM, MountPoint: tmp, HostKeyManager: p.HKM,
	}
	if err := sshconn.TestConnection(cfg, p.Confirm); err != nil {
		cleanup()
		return nil, err
	}
	sess, err := sshconn.Mount(cfg)
	if err != nil {
		cleanup()
		return nil, err
	}
	dir := tmp
	if d := sess.Dir(); d != "" {
		dir, tmp = d, d
	}
	return &Conn{CipherDir: dir, sess: sess, tmp: tmp, ownsDir: ownsDir}, nil
}

// Close unmounts the ciphertext and drops the key. Safe to call twice.
func (c *Conn) Close() error {
	if c == nil || c.tmp == "" {
		return nil
	}
	err := c.sess.Unmount(c.tmp)
	c.sess.Close()
	if err == nil && c.ownsDir {
		os.Remove(c.tmp)
	}
	c.tmp = ""
	return err
}

func (c *Conn) confPath() string { return filepath.Join(c.CipherDir, "gocryptfs.conf") }

// HasVolume reports whether a volume was created here already.
func (c *Conn) HasVolume() bool {
	_, err := os.Stat(c.confPath())
	return err == nil
}

// InitParams for creating a new volume.
type InitParams struct {
	API  *apiclient.Client
	Info *apiclient.ServerInfo
	Keys *e2ee.Keys
	NPow int // scrypt cost; 0 = default
	// ConsentEscrow is asked before the master key is sealed to the organisation's key, with that
	// key's fingerprint. Nil or false: nothing is sealed. Under policy "escrow" (no recovery code)
	// the volume is then not created; under "both" the user keeps only the recovery code.
	ConsentEscrow func(fingerprint string) bool
}

// ErrEscrowDeclined: the server requires escrow and the user did not agree to it.
var ErrEscrowDeclined = errors.New("this server requires an escrow copy of your storage key and you did not agree; nothing was created")

// Result of Init.
type InitResult struct {
	// RecoveryCode is empty when the operator's policy is escrow-only: the user gets no code.
	RecoveryCode string
	Escrow       bool
}

// Init creates a volume. Everything the server must know (recovery proof, escrow blob) is uploaded
// BEFORE the volume files are written, so a failure cannot leave a volume without a way to recover it.
func Init(c *Conn, p InitParams) (*InitResult, error) {
	if c.HasVolume() {
		return nil, errors.New("this account already has a volume")
	}
	seal := false
	policy := p.Info.RecoveryPolicy
	if policy == "escrow" || policy == "both" {
		if p.Info.EscrowPublicKey == nil {
			return nil, errors.New("the server requires escrow but did not give a key")
		}
		fp, err := escrowcheck.Fingerprint(*p.Info.EscrowPublicKey)
		if err != nil {
			return nil, err
		}
		// Asked before anything is uploaded, so a "no" leaves no trace on the server
		seal = p.ConsentEscrow != nil && p.ConsentEscrow(fp)
		if !seal && policy == "escrow" {
			return nil, ErrEscrowDeclined
		}
	}
	mk, err := e2ee.NewMasterKey()
	if err != nil {
		return nil, err
	}
	defer wipe(mk)

	proof, err := e2ee.RecoveryProof(mk)
	if err != nil {
		return nil, err
	}
	if err := p.API.PutRecoveryVerifier(proof); err != nil {
		var apiErr *apiclient.APIError
		if errors.As(err, &apiErr) && apiErr.Detail == "TOTP_REQUIRED" {
			// replacing an earlier verifier needs a fresh second factor: the sign-in was too long ago
			return nil, errors.New("storing the recovery verifier needs a fresh sign-in; nothing was created, run this again")
		}
		return nil, fmt.Errorf("storing the recovery verifier: %w", err)
	}
	res := &InitResult{}
	if seal {
		blob, err := e2ee.SealToEscrow(mk, *p.Info.EscrowPublicKey)
		if err != nil {
			return nil, err
		}
		if err := p.API.PutEscrow(blob); err != nil {
			return nil, fmt.Errorf("storing the escrow copy: %w", err)
		}
		res.Escrow = true
	}

	nPow := p.NPow
	if nPow == 0 {
		nPow = e2ee.DefaultScryptNPow
	}
	conf, err := e2ee.MakeConf(mk, p.Keys.VolumePassphrase, nPow)
	if err != nil {
		return nil, err
	}
	diriv := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, diriv); err != nil {
		return nil, err
	}
	if err := e2ee.WriteVolumeFiles(c.CipherDir, conf, diriv); err != nil {
		return nil, err
	}
	// A volume that failed its check is taken away again: otherwise running setup again would find
	// it, say the storage already exists and never show the recovery code
	undo := func(err error) (*InitResult, error) {
		os.Remove(filepath.Join(c.CipherDir, "gocryptfs.conf"))  //nolint
		os.Remove(filepath.Join(c.CipherDir, "gocryptfs.diriv")) //nolint
		return nil, err
	}

	// Prove the volume works before telling the user it does
	plain, done, err := checkPoint("cryptstorage-plain-")
	if err != nil {
		return undo(err)
	}
	defer done()
	if err := e2ee.MountVolume(c.CipherDir, plain, p.Keys.VolumePassphrase); err != nil {
		return undo(fmt.Errorf("the new volume does not mount: %w", err))
	}
	werr := e2ee.WriteCanary(plain)
	cerr := e2ee.CheckCanary(plain)
	if uerr := e2ee.UnmountVolume(plain); uerr != nil {
		return undo(uerr)
	}
	if werr != nil || cerr != nil {
		return undo(fmt.Errorf("the new volume does not work: %v %v", werr, cerr))
	}

	if policy == "user" || policy == "both" {
		code, err := e2ee.RecoveryCode(mk)
		if err != nil {
			return nil, err
		}
		res.RecoveryCode = code
	}
	return res, nil
}

// Unlock checks the passphrase against gocryptfs.conf (with limits on a hostile config) and mounts
// the plaintext view at plainDir.
func Unlock(c *Conn, keys *e2ee.Keys, plainDir string) error {
	conf, err := os.ReadFile(c.confPath())
	if err != nil {
		return errors.New("no volume found for this account: run init-storage first")
	}
	if mk, err := e2ee.ReadMasterKey(conf, keys.VolumePassphrase); err != nil {
		return err
	} else {
		wipe(mk)
	}
	// A previous config left by an older client or an interrupted change would let the old password in
	if err := DropBackup(c); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not remove the previous volume config from the server: %v\n", err)
	}
	if err := e2ee.MountVolume(c.CipherDir, plainDir, keys.VolumePassphrase); err != nil {
		return err
	}
	// The passphrase opened gocryptfs.conf, so the key is right: put back a check file the user deleted,
	// so that a later recovery can rely on it (e2ee.VerifyKey)
	if err := e2ee.CheckCanary(plainDir); errors.Is(err, fs.ErrNotExist) {
		if err := e2ee.WriteCanary(plainDir); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: could not restore the volume's check file: %v\n", err)
		}
	}
	return nil
}

// Rewrap changes the passphrase of the volume. The data is not re-encrypted. The old config is kept as
// gocryptfs.conf.bak until the caller has finished the change and calls DropBackup; Restore puts it back
// if a later step fails.
func Rewrap(c *Conn, oldPass, newPass []byte) (restore func() error, err error) {
	conf, err := os.ReadFile(c.confPath())
	if err != nil {
		return nil, err
	}
	mk, err := e2ee.ReadMasterKey(conf, oldPass)
	if err != nil {
		return nil, err
	}
	defer wipe(mk)
	return replaceConf(c, conf, mk, newPass)
}

func replaceConf(c *Conn, oldConf, mk, newPass []byte) (func() error, error) {
	newConf, err := e2ee.MakeConf(mk, newPass, e2ee.DefaultScryptNPow)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(c.confPath()+".bak", oldConf, 0o600); err != nil {
		return nil, err
	}
	tmp := c.confPath() + ".new"
	if err := os.WriteFile(tmp, newConf, 0o600); err != nil {
		return nil, err
	}
	if err := os.Rename(tmp, c.confPath()); err != nil {
		return nil, err
	}
	return func() error { return os.WriteFile(c.confPath(), oldConf, 0o600) }, nil
}

// Recover re-wraps the volume under newPass using the master key from the recovery code. The key is
// first checked by mounting read-only and reading the canary: gocryptfs would accept a wrong one.
func Recover(c *Conn, masterKey, newPass []byte) (restore func() error, err error) {
	oldConf, err := os.ReadFile(c.confPath())
	if err != nil {
		return nil, errors.New("no volume found for this account")
	}
	plain, done, err := checkPoint("cryptstorage-check-")
	if err != nil {
		return nil, err
	}
	defer done()
	if err := e2ee.MountVolumeWithMasterKey(c.CipherDir, plain, masterKey, true); err != nil {
		return nil, fmt.Errorf("the recovery code does not open this volume: %w", err)
	}
	cerr := e2ee.VerifyKey(c.CipherDir, plain)
	if uerr := e2ee.UnmountVolume(plain); uerr != nil {
		return nil, uerr
	}
	if cerr != nil {
		return nil, fmt.Errorf("the recovery code does not open this volume: %w", cerr)
	}
	restore, err = replaceConf(c, oldConf, masterKey, newPass)
	if err != nil {
		return nil, err
	}
	// Prove the new passphrase works; otherwise put the old config back
	check, doneCheck, err := checkPoint("cryptstorage-check-")
	if err != nil {
		restore()
		return nil, err
	}
	defer doneCheck()
	if err := e2ee.MountVolume(c.CipherDir, check, newPass); err != nil {
		restore()
		return nil, fmt.Errorf("the new passphrase does not open the volume (old config restored): %w", err)
	}
	cerr = e2ee.VerifyKey(c.CipherDir, check)
	if cerr == nil && errors.Is(e2ee.CheckCanary(check), fs.ErrNotExist) {
		e2ee.WriteCanary(check) // the key is verified; best effort, Unlock tries again
	}
	e2ee.UnmountVolume(check)
	if cerr != nil {
		restore()
		return nil, fmt.Errorf("verification failed (old config restored): %w", cerr)
	}
	if err := DropBackup(c); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not remove the previous volume config from the server: %v\n", err)
	}
	return restore, nil
}

// DropBackup removes gocryptfs.conf.bak, the previous config Rewrap and Recover keep on the server
// while a change is under way. Left there, the old password would keep opening the volume.
// Restore still works afterwards: it writes the old config from memory.
func DropBackup(c *Conn) error {
	err := os.Remove(c.confPath() + ".bak")
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return err
}

// checkPoint is where a volume is mounted for a moment to check it, and done tidies up after the
// unmount. On Windows it is a free drive letter: a folder there is a mount point (a junction) in the
// user's temp folder, which Windows may refuse to traverse ("the path cannot be traversed because it
// contains an untrusted mount point", RedirectionGuard, seen on Windows 11 26200).
func checkPoint(prefix string) (dir string, done func(), err error) {
	if runtime.GOOS == "windows" {
		d, err := freeDrive()
		return d, func() {}, err
	}
	d, err := os.MkdirTemp("", prefix)
	if err != nil {
		return "", nil, err
	}
	return d, func() { os.Remove(d) }, nil
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
