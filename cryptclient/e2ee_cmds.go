package main

// Commands for end-to-end encrypted storage (docs/design-e2ee.md). The server stores only
// ciphertext; one password becomes a login key (sent) and a volume passphrase (never sent).

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/term"

	"cryptclient/apiclient"
	"cryptclient/browserlogin"
	"cryptclient/crypto"
	"cryptclient/e2ee"
	"cryptclient/sshconn"
	"cryptclient/stickkey"
	"cryptclient/usb"
	"cryptclient/volume"
)

const minPasswordLen = 12

var stdin = bufio.NewReader(os.Stdin)

func promptLine(label string) string {
	fmt.Print(label)
	s, _ := stdin.ReadString('\n')
	return strings.TrimSpace(s)
}

// promptPassword asks again when nothing was typed (just Enter), and stops after passwordTries empty
// answers, before any other question is asked.
func promptPassword(label string) string {
	for try := 1; ; try++ {
		fmt.Print(label)
		b, err := term.ReadPassword(int(syscall.Stdin))
		fmt.Println()
		if err != nil {
			fatal("Could not read the password: %v", err)
		}
		if len(b) > 0 {
			return string(b)
		}
		if try == passwordTries {
			fatal("No password was typed.")
		}
		fmt.Println("The password is empty. Type it again.")
	}
}

// promptNewPassword asks twice and enforces the minimum length. The password protects the data
// against whoever holds a copy of the server's files, so it must not be short. A short or mistyped
// password is asked again, so the command does not have to start over.
func promptNewPassword(label string) string {
	for {
		pw := promptPassword(label)
		if len(pw) < minPasswordLen {
			fmt.Printf("The password must be at least %d characters. A sentence of a few words works well.\n", minPasswordLen)
			continue
		}
		if promptPassword("Type it again: ") != pw {
			fmt.Println("The passwords do not match. Try again.")
			continue
		}
		return pw
	}
}

// isYes accepts y and yes, in any case.
func isYes(answer string) bool {
	a := strings.ToLower(strings.TrimSpace(answer))
	return a == "y" || a == "yes"
}

func confirmHostKey(hostname, fingerprint string) bool {
	fmt.Println()
	return terminal.Confirm(hostKeyQuestion(hostname, fingerprint))
}

func readLine() string {
	s, _ := stdin.ReadString('\n')
	return s
}

// newAPI builds the API client with the stick's TLS pin, when there is a stick.
func newAPI(usbMount string) *apiclient.Client {
	pin := ""
	if usbMount != "" {
		pin = loadCertPin(usbMount)
	}
	return apiclient.New(serverURL(), "", pin)
}

func requireE2EE(api *apiclient.Client) *apiclient.ServerInfo {
	info, err := checkE2EE(api)
	if err != nil {
		fatal("%v", err)
	}
	return info
}

func checkE2EE(api *apiclient.Client) (*apiclient.ServerInfo, error) {
	info, err := api.ServerInfo()
	if err != nil {
		return nil, fmt.Errorf("Could not reach the server: %v", err)
	}
	if info.StorageMode != "e2ee" {
		return nil, errors.New("This server does not use end-to-end encryption.")
	}
	return info, nil
}

// loginE2EE logs in with the derived login key and asks for a two-factor code when needed.
func loginE2EE(api *apiclient.Client, username string, keys *e2ee.Keys) error {
	return loginWith(terminal, api, username, keys)
}

func loginWith(a asker, api *apiclient.Client, username string, keys *e2ee.Keys) error {
	_, err := api.Login(username, keys.AuthKey, "")
	if !errors.Is(err, apiclient.ErrTOTPRequired) {
		return err
	}
	label := "Verification code (authenticator app or backup code): "
	pk, perr := api.PasskeyBegin(username, keys.AuthKey)
	if perr == nil && pk.ApproveURL != "" {
		label = "Press Enter to approve with your passkey in the browser, or type the code from your authenticator app: "
	}
	code, aerr := a.Line(label)
	if aerr != nil {
		return aerr
	}
	if code = strings.TrimSpace(code); code == "" && perr == nil && pk.ApproveURL != "" {
		return browserlogin.Approve(context.Background(),
			browserlogin.Request{ApproveURL: pk.ApproveURL, Options: pk.Options, Username: username}, nil,
			func(page string) {
				fmt.Fprintf(os.Stderr, "Approve the sign-in in your browser. If it did not open, open this address:\n%s\n", page)
				if n, ok := a.(interface{ Notify(string) }); ok {
					n.Notify("Approve the sign-in in your browser. If it did not open, open " + page)
				}
			},
			func(cred json.RawMessage) error { return api.PasskeyFinish(pk.Session, cred) })
	}
	_, err = api.Login(username, keys.AuthKey, code)
	return err
}

// asker is where the connect flow asks its questions: the terminal, or the desktop dialogs when it
// was started without one (cryptclient tray).
type asker interface {
	Line(label string) (string, error)
	Confirm(question string) bool
}

type terminalAsker struct{}

var terminal asker = terminalAsker{}

func (terminalAsker) Line(label string) (string, error) {
	return promptLine(label), nil
}

func (terminalAsker) Confirm(question string) bool {
	fmt.Print(question + " (yes/no): ")
	return isYes(readLine())
}

func hostKeyQuestion(hostname, fingerprint string) string {
	return fmt.Sprintf("This is the first connection to %s.\nIts key fingerprint is:\n  %s\n"+
		"Check it against the one your administrator gave you. Trust it?", hostname, fingerprint)
}

// stick is a cryptkey stick and its password. pem is the decrypted key: for a sealed key it is nil
// until open, after the login.
type stick struct {
	device    string
	usbMount  string
	blob      []byte
	pem       []byte
	password  string
	oldFormat bool // the key uses the older, weaker password protection (upgrade-key)
}

// errWrongPassword means the password does not open the key on the stick.
var errWrongPassword = errors.New("Wrong password, or the stick is damaged.")

func unlockStick(password string) *stick {
	devicePath, err := findStick()
	if err != nil {
		fatal("%v", err)
	}
	st, err := openStick(devicePath, password)
	if err != nil {
		fatal("%v", err)
	}
	return st
}

// findStick returns the stick's device: the one the udev rule named, or the first one found.
func findStick() (string, error) {
	if p := os.Getenv("CRYPTCLIENT_DEVICE"); p != "" {
		return p, nil
	}
	dev, err := usb.FindCryptDevice()
	if err != nil {
		return "", fmt.Errorf("USB stick not found: %v\nPlease insert your stick.", err)
	}
	return dev.Path, nil
}

// openStick checks the stick and decrypts its key with the password.
func openStick(devicePath, password string) (*stick, error) {
	if err := usb.VerifySerialBinding(devicePath); err != nil {
		return nil, fmt.Errorf("The stick failed its check:\n%v", err)
	}
	blob, err := usb.ReadEncryptedKey(devicePath)
	if err != nil {
		return nil, fmt.Errorf("Could not read the stick: %v", err)
	}
	st := &stick{device: devicePath, usbMount: getUSBMountPath(devicePath), blob: blob, password: password,
		oldFormat: crypto.NeedsUpgrade(blob)}
	if stickkey.Sealed(blob) {
		return st, nil // the password is checked by the login, the key opens after it
	}
	if st.pem, err = crypto.DecryptKey(blob, password); err != nil {
		return nil, errWrongPassword
	}
	return st, nil
}

func (s *stick) wipe() {
	for i := range s.pem {
		s.pem[i] = 0
	}
}

func publicKeyOf(pem []byte) (string, error) {
	signer, err := ssh.ParsePrivateKey(pem)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey()))), nil
}

// registerKey stores the stick's public key. A replaced key waits; that is a normal step, so it
// is explained and the command ends without an error, as nothing more can be done until then.
func registerKey(api *apiclient.Client, pub, loginKey string) {
	err := api.RegisterKey(pub, loginKey)
	var wait *apiclient.KeyPendingError
	if errors.As(err, &wait) {
		fmt.Println()
		for _, line := range wait.Explain() {
			fmt.Println(line)
		}
		os.Exit(0)
	}
	if err != nil {
		fatal("Could not register the stick's key: %v", err)
	}
}

func hostKeys(usbMount string) *sshconn.HostKeyManager {
	hkm := sshconn.NewHostKeyManager(usbMount)
	if !hkm.Persistent() {
		fmt.Println("Warning: the stick's file system is not mounted, so the server's key cannot be remembered.")
	}
	if err := hkm.Load(); err != nil {
		fmt.Printf("Warning: could not load the stored server keys: %v\n", err)
	}
	return hkm
}

// --- register ---

func cmdRegister() {
	api := newAPI("")
	requireE2EE(api)
	username := promptLine("Choose a username: ")
	email := promptLine("E-mail address: ")
	password := promptNewPassword("Choose a password: ")
	keys, err := e2ee.Derive(username, password)
	if err != nil {
		fatal("%v", err)
	}
	if err := api.Register(username, email, keys.AuthKey); err != nil {
		fatal("Registration failed: %v", err)
	}
	fmt.Println("✓ Account created. Check your e-mail and confirm the address, then run:")
	fmt.Println("    cryptclient init-usb      (once, prepares your stick)")
	fmt.Println("    cryptclient init-storage  (once, creates your encrypted storage)")
}

// --- init-storage ---

func cmdInitStorage() {
	refuseElevated()
	api := newAPI("")
	username := promptLine("Username: ")
	password := promptPassword("Password: ")
	st := unlockStick(password)
	defer st.wipe()
	api = newAPI(st.usbMount)
	info := requireE2EE(api)
	if err := checkStickServer(st.usbMount, info); err != nil {
		fatal("%v", err)
	}
	keys, err := e2ee.Derive(username, password)
	if err != nil {
		fatal("%v", err)
	}
	if err := loginE2EE(api, username, keys); err != nil {
		fatal("Login failed: %v", err)
	}
	if err := st.open(terminal, api); err != nil {
		fatal("%v", err)
	}
	pub, err := publicKeyOf(st.pem)
	if err != nil {
		fatal("%v", err)
	}
	registerKey(api, pub, keys.AuthKey)
	storage, err := api.E2EEStorage()
	if err != nil {
		fatal("%v", err)
	}
	conn, err := volume.Connect(volume.ConnectParams{Storage: storage, PEM: st.pem, HKM: hostKeys(st.usbMount), Confirm: confirmHostKey})
	if err != nil {
		fatal("Could not connect to the server: %v", err)
	}
	defer conn.Close()
	say := func(msg string) { fmt.Println(msg) }
	st.seal(api, say) // after the server took the key
	rememberStickServer(st.usbMount, info, storage.SSHHostKeys, say)

	fmt.Println("Creating your encrypted storage...")
	res, err := volume.Init(conn, volume.InitParams{API: api, Info: info, Keys: keys, ConsentEscrow: escrowConsent(terminal)})
	if err != nil {
		fatal("%v", err)
	}
	rememberEscrow(st.usbMount, info)
	fmt.Println("✅ Your encrypted storage is ready. Only you can read what you put in it.")
	if res.RecoveryCode != "" {
		fmt.Println("\nWRITE DOWN YOUR RECOVERY CODE and keep it somewhere safe, apart from your stick and password:")
		fmt.Printf("\n    %s\n\n", res.RecoveryCode)
		fmt.Println("It is shown only once. If you forget your password, this code is the only way back to your files.")
	}
	if res.Escrow {
		fmt.Println("\nNote: your organisation keeps a sealed recovery copy. Its administrators can restore your access")
		fmt.Println("if you lose your password. This is set by your organisation.")
	}
}

// --- connect ---

type activeVolume struct {
	conn     *volume.Conn
	plain    string
	api      *apiclient.Client // logged in; the sync lock is renewed through it
	username string
	sync     *syncSession
}

var openVolume *activeVolume

// openE2EE logs in, connects to the server and unlocks the storage at the mount point. The questions
// on the way (verification code, an unknown server key) go to a.
func openE2EE(a asker, st *stick, username string) error {
	api := newAPI(st.usbMount)
	info, err := checkE2EE(api)
	if err != nil {
		return err
	}
	if err := checkStickServer(st.usbMount, info); err != nil {
		return err
	}
	if err := checkEscrow(a, st.usbMount, info); err != nil {
		return err
	}
	keys, err := e2ee.Derive(username, st.password)
	if err != nil {
		return err
	}
	if err := loginWith(a, api, username, keys); err != nil {
		return fmt.Errorf("Login failed: %w", err)
	}
	if err := st.open(a, api); err != nil {
		return err
	}
	tell := func(msg string) { fmt.Println(msg) }
	if n, ok := a.(interface{ Notify(string) }); ok {
		tell = n.Notify // the tray: a desktop notice
	}
	storage, err := api.E2EEStorage()
	if err != nil {
		return err
	}
	confirm := func(hostname, fingerprint string) bool { return a.Confirm(hostKeyQuestion(hostname, fingerprint)) }
	conn, err := volume.Connect(volume.ConnectParams{Storage: storage, PEM: st.pem, HKM: hostKeys(st.usbMount), Confirm: confirm})
	if err != nil {
		return fmt.Errorf("Could not connect to the server: %w", err)
	}
	// only now: the server took the stick's key for this account, so it is the stick's own server
	st.seal(api, tell)
	rememberStickServer(st.usbMount, info, storage.SSHHostKeys, tell)
	mountPoint := getMountPoint()
	if isDriveLetter(mountPoint) {
		// cppcryptfs mounts the drive letter itself
	} else if err := os.MkdirAll(mountPoint, 0o700); err != nil {
		conn.Close()
		return fmt.Errorf("Could not create %s: %v", mountPoint, err)
	}
	if err := volume.Unlock(conn, keys, mountPoint); err != nil {
		conn.Close()
		if errors.Is(err, e2ee.ErrWrongPassphrase) {
			return errors.New("The password does not open the storage.")
		}
		return err
	}
	openVolume = &activeVolume{conn: conn, plain: mountPoint, api: api, username: username}
	return nil
}

// stayConnected keeps the storage open until the stick is removed or the process is told to stop
// (Ctrl+C, systemd stopping the tray service, or stop closed: Disconnect in the Windows tray), then
// disconnects. before is called first, and is told whether the stick was removed.
func stayConnected(device string, stop <-chan struct{}, before func(removed bool)) {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	ejected := make(chan struct{})
	go usb.WatchEject(device, 2*time.Second, func() { close(ejected) })
	defer signal.Stop(sigCh)
	removed := false
	select {
	case <-sigCh:
	case <-stop:
	case <-ejected:
		removed = true
	}
	before(removed)
	disconnectE2EE()
}

func disconnectE2EE() {
	if openVolume == nil {
		return
	}
	// rclone must be done with the volume before it is unmounted; an interrupted run recovers next time
	openVolume.sync.stop()
	if err := e2ee.UnmountVolume(openVolume.plain); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not unmount %s: %v\n", openVolume.plain, err)
	}
	if err := openVolume.conn.Close(); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not close the server connection: %v\n", err)
	}
	openVolume = nil
	fmt.Println("✓ Disconnected.")
}

// --- change-password ---

func cmdChangePassword() {
	refuseElevated()
	username := promptLine("Username: ")
	oldPw := promptPassword("Current password: ")
	st := unlockStick(oldPw)
	defer st.wipe()
	api := newAPI(st.usbMount)
	if err := checkStickServer(st.usbMount, requireE2EE(api)); err != nil {
		fatal("%v", err)
	}
	newPw := promptNewPassword("New password: ")
	oldKeys, _ := e2ee.Derive(username, oldPw)
	newKeys, err := e2ee.Derive(username, newPw)
	if err != nil || oldKeys == nil {
		fatal("could not derive keys")
	}
	if err := loginE2EE(api, username, oldKeys); err != nil {
		fatal("Login failed: %v", err)
	}
	if err := st.open(terminal, api); err != nil {
		fatal("%v", err)
	}
	storage, err := api.E2EEStorage()
	if err != nil {
		fatal("%v", err)
	}
	conn, err := volume.Connect(volume.ConnectParams{Storage: storage, PEM: st.pem, HKM: hostKeys(st.usbMount), Confirm: confirmHostKey})
	if err != nil {
		fatal("Could not connect to the server: %v", err)
	}
	defer conn.Close()
	st.seal(api, func(msg string) { fmt.Println(msg) }) // after the server took the key
	// The key for the new password, made now: once the password changes, this session ends
	newBlob, err := crypto.EncryptKey(st.pem, newPw)
	if stickkey.Sealed(st.blob) {
		newBlob, err = stickkey.Reseal(api, st.blob, st.pem, newPw)
	}
	if err != nil {
		fatal("Could not prepare the stick's key for the new password: %v", err)
	}
	restore, err := volume.Rewrap(conn, oldKeys.VolumePassphrase, newKeys.VolumePassphrase)
	if err != nil {
		fatal("%v", err)
	}
	err = api.ChangeLoginKey(oldKeys.AuthKey, newKeys.AuthKey, "")
	if errors.Is(err, apiclient.ErrTOTPRequired) {
		err = api.ChangeLoginKey(oldKeys.AuthKey, newKeys.AuthKey,
			promptLine("Verification code (authenticator app or backup code): "))
	}
	if err != nil {
		if rerr := restore(); rerr != nil {
			fatal("Server refused the change (%v) and the storage could not be restored: %v\nUse your recovery code.", err, rerr)
		}
		fatal("Password not changed: %v", err)
	}
	if err := volume.DropBackup(conn); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not remove the previous volume config from the server: %v\n", err)
		fmt.Fprintln(os.Stderr, "   It is removed the next time you connect.")
	}
	if err := writeKeyChecked(st.device, st.blob, newBlob); err != nil {
		fmt.Printf("⚠️  Your password was changed, but the stick still needs the OLD password: %v\n", err)
		fmt.Println("   Run this command again to finish.")
		return
	}
	fmt.Println("✅ Password changed. Your stick and your storage now use the new password.")
}

// --- recover ---

func cmdRecoverE2EE() {
	refuseElevated()
	username := promptLine("Username: ")
	code := promptLine("Recovery code: ")
	mk, err := e2ee.ParseRecoveryCode(code)
	if err != nil {
		fatal("%v", err)
	}
	proof, _ := e2ee.RecoveryProof(mk)
	newPw := promptNewPassword("Choose a NEW password: ")
	keys, err := e2ee.Derive(username, newPw)
	if err != nil {
		fatal("%v", err)
	}

	devicePath := os.Getenv("CRYPTCLIENT_DEVICE")
	if devicePath == "" {
		dev, err := usb.FindCryptDevice()
		if err != nil {
			fatal("USB stick not found: %v\nInsert your stick (a new stick needs `cryptclient init-usb` first, with the NEW password), then run this again.", err)
		}
		devicePath = dev.Path
	}
	usbMount := getUSBMountPath(devicePath)
	api := newAPI(usbMount)
	info := requireE2EE(api)
	if err := checkStickServer(usbMount, info); err != nil {
		fatal("%v", err)
	}

	// Safe to repeat: if the server already accepted the new password, skip the reset.
	if err := loginE2EE(api, username, keys); err != nil {
		err := api.RecoverE2EE(username, proof, keys.AuthKey, "")
		if errors.Is(err, apiclient.ErrTOTPRequired) {
			// The recovery code replaces the password, not the second factor
			err = api.RecoverE2EE(username, proof, keys.AuthKey,
				promptLine("Verification code (authenticator app or backup code): "))
		}
		if err != nil {
			fatal("Recovery failed: %v", err)
		}
		if err := loginE2EE(api, username, keys); err != nil {
			fatal("Login with the new password failed: %v", err)
		}
	}

	// The old key on the stick is protected by the forgotten password: use a fresh key.
	var pem []byte
	var oldBlob []byte
	if blob, err := usb.ReadEncryptedKey(devicePath); err == nil {
		oldBlob = blob
		pem, _ = stickkey.Open(api, blob, newPw) // works if init-usb was just run with the new password
	}
	reused := pem != nil // the stick's own key, not a new one
	if pem == nil {
		fmt.Printf("The key on the stick is locked by your old password. Replace it with a new one? Files on the stick's other partition are not touched. (yes/no): ")
		if !isYes(readLine()) {
			fatal("Stopped. Run this again when you are ready.")
		}
		// the new key goes where the old one is (the stick was found by it), so nothing else is touched
		_, newPEM, err := generateSSHKeyPair()
		if err != nil {
			fatal("%v", err)
		}
		host, _ := os.Hostname()
		blob, err := stickkey.Seal(api, newPEM, newPw, host)
		if errors.Is(err, apiclient.ErrNoStickSecrets) {
			blob, err = crypto.EncryptKey(newPEM, newPw)
		}
		if err != nil {
			fatal("%v", err)
		}
		if err := usb.WriteEncryptedKey(devicePath, blob); err != nil {
			fatal("Writing to the stick failed: %v", err)
		}
		pem = newPEM
	}
	defer func() {
		for i := range pem {
			pem[i] = 0
		}
	}()
	pub, err := publicKeyOf(pem)
	if err != nil {
		fatal("%v", err)
	}
	registerKey(api, pub, keys.AuthKey)
	storage, err := api.E2EEStorage()
	if err != nil {
		fatal("%v", err)
	}
	conn, err := volume.Connect(volume.ConnectParams{Storage: storage, PEM: pem, HKM: hostKeys(usbMount), Confirm: confirmHostKey})
	if err != nil {
		fatal("Could not connect to the server: %v", err)
	}
	defer conn.Close()
	say := func(msg string) { fmt.Println(msg) }
	if reused && !stickkey.Sealed(oldBlob) {
		st := &stick{device: devicePath, usbMount: usbMount, blob: oldBlob, pem: pem, password: newPw}
		st.seal(api, say) // after the server took the key
	}
	rememberStickServer(usbMount, info, storage.SSHHostKeys, say)
	if _, err := volume.Recover(conn, mk, keys.VolumePassphrase); err != nil {
		fatal("%v", err)
	}
	fmt.Println("✅ Recovered. Your files are intact and the new password now opens them.")
	fmt.Println("   Run `cryptclient connect` as usual.")
}
