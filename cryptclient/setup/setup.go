// Package setup is the guided first-time setup: account, USB stick, encrypted storage and the
// recovery code, in one conversation. It can be repeated: every step first checks whether it is
// already done, so a user who stopped halfway (waiting for the confirmation e-mail, say) continues
// where they left off.
//
// Everything that touches the terminal, the USB stick or the machine goes through the interfaces
// below, so the whole flow is tested against the real server with a scripted user and a fake stick.
package setup

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"cryptclient/apiclient"
	"cryptclient/e2ee"
	"cryptclient/escrowcheck"
	"cryptclient/sshconn"
	"cryptclient/stickkey"
	"cryptclient/stickserver"
	"cryptclient/volume"
)

const MinPasswordLen = 12

// UI is the conversation with the user.
type UI interface {
	Say(format string, args ...any)
	Ask(label string) string
	AskSecret(label string) string
	Confirm(label string) bool // yes / no
}

// Stick is the USB key stick.
type Stick interface {
	// Present reports whether a prepared stick is plugged in.
	Present() bool
	// ReadKey returns the encrypted key blob of the present stick.
	ReadKey() ([]byte, error)
	// Prepare lets the user pick a device and writes a NEW key protected by password to it.
	// It returns the unencrypted private key (PEM) and its public key line. confirmed: the user already
	// agreed to replace the key on the present stick, so it is not asked again.
	Prepare(password string, confirmed bool) (pem []byte, pub string, err error)
	// MountPath is where the stick's data partition is mounted (host keys and TLS pin live there).
	MountPath() string
	// WriteKey replaces the key blob old with blob, and checks it reads back (sealing).
	WriteKey(old, blob []byte) error
}

// Env is everything the flow needs from the outside world.
type Env struct {
	UI       UI
	Stick    Stick
	API      func(usbMount string) *apiclient.Client
	HostKeys func(usbMount string) *sshconn.HostKeyManager
	Trust    func(hostname, fingerprint string) bool
	// Missing lists what must be installed before anything else can work (empty = all there).
	Missing func() []string
	// MaxVerifyTries bounds the wait for the confirmation e-mail (0 = 20).
	MaxVerifyTries int
}

// Result tells the caller what happened.
type Result struct {
	Username     string
	NewAccount   bool
	NewVolume    bool
	RecoveryCode string
	Escrow       bool
	KeyPending   bool // the stick's key replaced an older one and starts working after the safety wait
}

var ErrAborted = errors.New("setup stopped")

func fail(ui UI, err error, hint string) error {
	ui.Say("")
	ui.Say("Something went wrong: %v", err)
	if hint != "" {
		ui.Say("%s", hint)
	}
	return err
}

// Run walks through the setup.
func Run(env Env) (*Result, error) {
	ui := env.UI
	ui.Say("Welcome. This sets up your private, encrypted storage in a few steps.")
	ui.Say("Only you will be able to read what you store: not even the server's administrators can.")
	ui.Say("")

	// 1. The machine
	if missing := env.Missing(); len(missing) > 0 {
		ui.Say("Before we start, this computer needs a few things:")
		for _, m := range missing {
			ui.Say("  - %s", m)
		}
		ui.Say("Install them, then run this setup again.")
		return nil, fail(ui, errors.New("missing requirements"), "")
	}

	// 2. The server
	api := env.API("")
	info, err := api.ServerInfo()
	if err != nil {
		return nil, fail(ui, fmt.Errorf("cannot reach the server: %w", err), "Check your internet connection and the server address (CRYPTSTORAGE_SERVER in the settings file).")
	}
	if info.StorageMode != "e2ee" {
		return nil, fail(ui, errors.New("this server does not use end-to-end encryption"), "")
	}

	// 3. Who you are
	res := &Result{}
	username := strings.TrimSpace(ui.Ask("Choose a username (letters, digits and _): "))
	if username == "" {
		return nil, ErrAborted
	}
	res.Username = username
	password := ui.AskSecret("Choose a password: ")
	if len(password) < MinPasswordLen {
		return nil, fail(ui, fmt.Errorf("the password must be at least %d characters", MinPasswordLen),
			"A sentence of a few words works well, for example: purple tractors sing quietly.")
	}
	keys, err := e2ee.Derive(username, password)
	if err != nil {
		return nil, fail(ui, err, "")
	}

	// 4. The account
	err = login(api, ui, username, keys)
	switch {
	case err == nil:
		ui.Say("You already have an account: continuing.")
	case isNotVerified(err):
		if err := waitForVerification(env, api, username, keys); err != nil {
			return nil, err
		}
	case strings.Contains(err.Error(), "Invalid username or password"):
		ui.Say("There is no account with that name and password yet.")
		if !ui.Confirm("Create a new account? (yes/no): ") {
			return nil, fail(ui, errors.New("wrong password for an existing account?"), "Run setup again with the right password.")
		}
		if ui.AskSecret("Type the password again: ") != password {
			return nil, fail(ui, errors.New("the two passwords differ"), "")
		}
		ui.Say("")
		ui.Say("Your files are encrypted with this password. Nobody can reset it for you.")
		ui.Say("If you forget it, only the recovery code you get at the end brings your files back.")
		email := strings.TrimSpace(ui.Ask("Your e-mail address: "))
		if err := api.Register(username, email, keys.AuthKey); err != nil {
			return nil, fail(ui, fmt.Errorf("could not create the account: %w", err), "")
		}
		res.NewAccount = true
		ui.Say("Account created. We sent a message to %s.", email)
		if err := waitForVerification(env, api, username, keys); err != nil {
			return nil, err
		}
	default:
		return nil, fail(ui, err, "")
	}

	// 5. The USB stick
	var pem, blob []byte
	var pub string
	replace := false // the user agreed to move a stick of another server to this one
	if env.Stick.Present() {
		if err := checkStickServer(env, api.BaseURL, info.ServerID); err != nil {
			if !errors.Is(err, errReplaceStick) {
				return nil, err
			}
			replace = true
		}
	}
	if env.Stick.Present() && !replace {
		if b, rerr := env.Stick.ReadKey(); rerr == nil {
			// a sealed key needs the stick secret, which the login above gives access to
			if p, derr := stickkey.Open(api, b, password); derr == nil {
				pem, blob = p, b
				ui.Say("Your USB stick is ready.")
			}
		}
	}
	if pem == nil {
		ui.Say("")
		ui.Say("Now the USB stick. It holds the key that lets this computer reach your storage.")
		ui.Say("Preparing it erases the key area of the stick (your other files on it stay).")
		if !res.NewAccount {
			ui.Say("If your account already has a stick, a newly prepared one starts working only after a safety")
			ui.Say("wait of about a day; the old stick keeps working until then.")
		}
		pem, pub, err = env.Stick.Prepare(password, replace)
		if err != nil {
			return nil, fail(ui, err, "Insert a USB stick and run setup again.")
		}
		blob, _ = env.Stick.ReadKey()
	}
	defer wipe(pem)
	if pub == "" {
		if pub, err = publicKey(pem); err != nil {
			return nil, fail(ui, err, "")
		}
	}
	usbMount := env.Stick.MountPath()
	rememberServer(env, usbMount, api.BaseURL, info.ServerID, nil)
	// The stick's client adds its TLS pin. It takes over the session of the sign-in above instead of
	// signing in again: a second sign-in asked for a second verification code, and the server refuses
	// a code that was already used, so typing the same code again failed (and the stick could not
	// be registered until the next code came up).
	pinned := env.API(usbMount)
	pinned.Token, pinned.RefreshToken = api.Token, api.RefreshToken
	api = pinned
	if api.Token == "" {
		if err := login(api, ui, username, keys); err != nil {
			return nil, fail(ui, err, "")
		}
	}
	if err := api.RegisterKey(pub, keys.AuthKey); err != nil {
		var wait *apiclient.KeyPendingError
		if !errors.As(err, &wait) {
			return nil, fail(ui, fmt.Errorf("could not register the stick: %w", err), "")
		}
		// a replaced key waits: a normal step, and setup has done all it can until then
		sealStick(env, api, blob, pem, password)
		ui.Say("")
		for _, line := range wait.Explain() {
			ui.Say("%s", line)
		}
		res.KeyPending = true
		return res, nil
	}
	sealStick(env, api, blob, pem, password)

	// 6. The storage
	storage, err := api.E2EEStorage()
	if err != nil {
		return nil, fail(ui, err, "")
	}
	conn, err := volume.Connect(volume.ConnectParams{Storage: storage, PEM: pem, HKM: env.HostKeys(usbMount), Confirm: env.Trust})
	if err != nil {
		return nil, fail(ui, fmt.Errorf("could not connect to the server: %w", err), "")
	}
	defer conn.Close()
	rememberServer(env, usbMount, api.BaseURL, info.ServerID, storage.SSHHostKeys)
	if conn.HasVolume() {
		ui.Say("Your encrypted storage already exists.")
		return res, nil
	}
	ui.Say("Creating your encrypted storage (this takes a moment)...")
	consent := func(fp string) bool {
		ui.Say("")
		for _, line := range strings.Split(escrowcheck.ConsentText(fp), "\n") {
			ui.Say("%s", line)
		}
		return ui.Confirm("Do you agree that your organisation keeps this copy? (yes/no): ")
	}
	init, err := volume.Init(conn, volume.InitParams{API: api, Info: info, Keys: keys, ConsentEscrow: consent})
	if err != nil {
		return nil, fail(ui, err, "")
	}
	// What the user has now seen; the client warns when the server's setting changes later
	if rec, rerr := escrowcheck.FromServer(info); rerr == nil && usbMount != "" {
		if serr := escrowcheck.Save(usbMount, rec); serr != nil {
			ui.Say("Warning: could not remember the escrow setting on the stick: %v", serr)
		}
	}
	res.NewVolume = true
	res.Escrow = init.Escrow
	res.RecoveryCode = init.RecoveryCode

	// 7. The recovery code
	if init.RecoveryCode != "" {
		if err := showRecoveryCode(ui, init.RecoveryCode); err != nil {
			return res, err
		}
	}
	if init.Escrow {
		ui.Say("")
		ui.Say("Note: your organisation keeps a sealed recovery copy, so its administrators can restore your")
		ui.Say("access if you lose your password. This is set by your organisation.")
	}
	ui.Say("")
	ui.Say("All done. To open your storage, insert the stick and run: cryptclient connect")
	ui.Say("Eject the stick safely before you pull it out (or move it out of a virtual machine).")
	return res, nil
}

var errReplaceStick = errors.New("prepare the stick for this server")

// checkStickServer looks at which server the present stick belongs to. A stick of another server is
// prepared for this one only when the user agrees (errReplaceStick); otherwise setup stops and says how to
// reach the stick's own server, so that the stick is never tied to a server by mistake.
func checkStickServer(env Env, url, serverID string) error {
	ui := env.UI
	rec, err := stickserver.Load(env.Stick.MountPath())
	if err != nil {
		return fail(ui, err, "")
	}
	err = stickserver.Check(rec, url, serverID)
	var other *stickserver.OtherServerError
	if !errors.As(err, &other) {
		return err
	}
	ui.Say("")
	if other.SameAddress {
		ui.Say("The USB stick was prepared for %s, but the server there has been set up again since,", url)
		ui.Say("so the key on the stick cannot open there any more.")
	} else {
		ui.Say("This USB stick belongs to another server: %s", other.StickURL)
		ui.Say("You are setting up %s. A stick serves one server at a time.", url)
	}
	if ui.Confirm(fmt.Sprintf("Prepare the stick for %s? Its old key is erased, so it no longer opens on the "+
		"other server. (yes/no): ", url)) {
		return errReplaceStick
	}
	return fail(ui, errors.New("the stick belongs to another server"), fmt.Sprintf(
		"Nothing was changed. To use the stick with its own server: cryptclient server %s, then cryptclient connect.",
		other.StickURL))
}

// rememberServer notes on the stick the server it is prepared for.
func rememberServer(env Env, mount, url, serverID string, hostKeys []string) {
	if mount == "" {
		return
	}
	rec, _ := stickserver.Load(mount)
	if rec != nil && stickserver.Check(rec, url, serverID) != nil {
		rec = nil // the stick was just prepared for this server: the old record is for the old key
	}
	next, changed := stickserver.Updated(rec, url, serverID, hostKeys)
	if !changed {
		return
	}
	if err := stickserver.Save(mount, next); err != nil {
		env.UI.Say("Note: could not note on the stick which server it belongs to (%v); connecting tries again.", err)
	}
}

// sealStick protects the stick's key with the server's stick secret, so that a lost or copied stick cannot
// be attacked offline. Best effort: connect tries again if it fails here.
func sealStick(env Env, api *apiclient.Client, blob, pem []byte, password string) {
	if blob == nil || stickkey.Sealed(blob) {
		return
	}
	host, _ := os.Hostname()
	sealed, err := stickkey.Seal(api, pem, password, host)
	if errors.Is(err, apiclient.ErrNoStickSecrets) {
		return
	}
	if err == nil {
		err = env.Stick.WriteKey(blob, sealed)
	}
	if err != nil {
		env.UI.Say("Note: the stick's key could not be protected by the server yet (%v); connecting tries again.", err)
	}
}

func login(api *apiclient.Client, ui UI, username string, keys *e2ee.Keys) error {
	_, err := api.Login(username, keys.AuthKey, "")
	if errors.Is(err, apiclient.ErrTOTPRequired) {
		_, err = api.Login(username, keys.AuthKey, strings.TrimSpace(ui.Ask("Verification code (authenticator app): ")))
	}
	return err
}

func isNotVerified(err error) bool {
	return err != nil && strings.Contains(err.Error(), "Email not verified")
}

// waitForVerification waits until the user has clicked the link in the e-mail.
func waitForVerification(env Env, api *apiclient.Client, username string, keys *e2ee.Keys) error {
	ui := env.UI
	tries := env.MaxVerifyTries
	if tries == 0 {
		tries = 20
	}
	for i := 0; i < tries; i++ {
		err := login(api, ui, username, keys)
		if err == nil {
			return nil
		}
		if !isNotVerified(err) {
			return fail(ui, err, "")
		}
		if i == 0 {
			ui.Say("Open the e-mail and click the confirmation link. Check the spam folder if it is not there.")
		} else {
			ui.Say("It is not confirmed yet.")
		}
		if !ui.Confirm("Have you confirmed it? (yes = check again, no = stop for now): ") {
			ui.Say("Okay. Run setup again after confirming; it continues from here.")
			return ErrAborted
		}
	}
	return fail(ui, errors.New("the e-mail was not confirmed"), "Run setup again after confirming it.")
}

// showRecoveryCode displays the code and insists that the user has copied it: a typed-back check of the
// first group, because a code that was never written down is the one thing that cannot be repaired later.
func showRecoveryCode(ui UI, code string) error {
	ui.Say("")
	ui.Say("WRITE DOWN YOUR RECOVERY CODE and keep it safe, apart from your stick and your password:")
	ui.Say("")
	ui.Say("    %s", code)
	ui.Say("")
	ui.Say("It is shown only once. If you forget your password, this code is the only way back to your files.")
	first := strings.SplitN(code, "-", 2)[0]
	for i := 0; i < 5; i++ {
		got := strings.ToUpper(strings.TrimSpace(ui.Ask("To check you have it, type the first group (before the first dash): ")))
		if got == first {
			ui.Say("Good.")
			return nil
		}
		ui.Say("That does not match. Look at the code above and try again.")
	}
	return fail(ui, errors.New("the recovery code was not confirmed"),
		"Your storage exists, but write the code down before you use it: "+code)
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
