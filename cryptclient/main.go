package main

import (
	"bytes"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	"cryptclient/apiclient"
	"cryptclient/crypto"
	"cryptclient/escrowcheck"
	"cryptclient/sshconn"
	"cryptclient/stickserver"
	"cryptclient/usb"

	"golang.org/x/term"
)

// Version is injected by the build script: -ldflags="-X main.Version=1.0.0"
var Version = "dev"

const defaultServer = "https://your-server.example.com"

func main() {
	loadEnvFile(envFilePath())
	if len(os.Args) < 2 && runtime.GOOS == "windows" && !hasConsole() {
		cmdTray() // CryptStorage.exe: the window program started from the Start menu or at sign-in
		return
	}
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "connect":
		cmdConnect()
	case "tray":
		cmdTray()
	case "disconnect":
		cmdDisconnect()
	case "status":
		cmdStatus()
	case "version":
		fmt.Printf("cryptclient %s\n", appVersion())
		os.Exit(0)
	case "init-usb":
		cmdInitUSB()
	case "check-device":
		cmdCheckDevice()
	case "upgrade-key":
		cmdUpgradeKey()
	case "setup":
		cmdSetup()
	case "diagnose":
		cmdDiagnose()
	case "install-deps":
		cmdInstallDeps()
	case "register":
		cmdRegister()
	case "init-storage":
		cmdInitStorage()
	case "change-password":
		cmdChangePassword()
	case "recover":
		cmdRecoverE2EE()
	case "web-login":
		cmdWebLogin()
	case "server":
		cmdServer()
	default:
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`CryptClient - Encrypted storage client

Usage:
  cryptclient setup        First-time setup, step by step (account, USB stick, storage, recovery code)
  cryptclient diagnose     Show what this computer has and lacks (for help requests)
  cryptclient install-deps Install the Windows components the client needs
  cryptclient connect      Connect storage (requires USB key + password)
      --sync               also keep the folder ~/CryptStorage synchronised with the storage while connected
      --allow-mass-delete  with --sync: confirm deleting more than half of the files (one run)
      --replace-unreadable with --sync: replace storage files that cannot be read with the local copy
  cryptclient disconnect   Disconnect storage
  cryptclient web-login    Sign in to the account web page without typing the password there
  cryptclient status       Show connection status
  cryptclient server [address]  Show the server address, or change it
  cryptclient init-usb     Initialize a USB stick as a cryptkey device
  cryptclient upgrade-key  Re-protect the key on the stick with the current (Argon2id) format
  cryptclient tray         Connect with desktop dialogs instead of the terminal (Linux: zenity;
                           Windows: the padlock next to the clock, normally started as CryptStorage.exe)
  cryptclient check-device Check if device is a cryptkey USB

Environment:
  CRYPTSTORAGE_SERVER   API server URL (setup and connect ask for it once and save it)
  CRYPTSTORAGE_CERT_PIN TLS pins, comma separated: sha256/<base64 public key> (preferred, survives
                        certificate renewal with the same key) or a leaf fingerprint; a second
                        pin (e.g. your CA's intermediate) works as a backup
  CRYPTSTORAGE_MOUNT    Mount point (default: ~/cryptstorage)
  CRYPTCLIENT_DEVICE    Device path (set by the udev rule's user service)
  CRYPTCLIENT_SYNC_DIR  Synchronised folder; setting it turns syncing on (also for the tray)
  CRYPTCLIENT_SYNC_INTERVAL  Seconds between synchronisations (default 60, at least 10)

These can also be set in ~/.config/cryptstorage/env, one NAME=value per line.`)
}

// cmdConnect is the main connection flow, in the terminal.
func cmdConnect() {
	refuseElevated()
	if err := askServer(promptLine, probeServer); err != nil {
		fatal("%v", err)
	}
	devicePath, err := findStick()
	if err != nil {
		fatal("%v", err)
	}
	if err := checkStickServerEarly(devicePath); err != nil {
		fatal("%v", err)
	}
	st, err := openStick(devicePath, promptPassword("Password: "))
	if err != nil {
		fatal("%v", err)
	}
	if st.pem != nil {
		fmt.Println("✓ Key unlocked.")
	}
	if st.oldFormat {
		fmt.Println("ℹ️  The key on this stick uses an older, weaker password protection.")
		fmt.Println("   Run `cryptclient upgrade-key` to upgrade it (it keeps a backup).")
	}
	username := savedUsername()
	if username != "" {
		if u := promptLine(fmt.Sprintf("Username [%s]: ", username)); u != "" {
			username = u
		}
	} else {
		username = promptLine("Username: ")
	}
	err = openE2EE(terminal, st, username)
	st.wipe()
	if err != nil {
		fatal("%v", err)
	}
	rememberUsername(username)

	// openVolume.plain, not getMountPoint() again: on Windows that now skips the drive just taken
	fmt.Printf("\n✅ Connected! Your storage is at: %s\n", openVolume.plain)
	maybeStartSync(terminal, func(msg string) { fmt.Println("   " + msg) })
	fmt.Println("   Remove the USB stick or press Ctrl+C to disconnect.")
	stayConnected(st.device, nil, func(removed bool) {
		if removed {
			fmt.Println("\nUSB stick removed - disconnecting...")
		} else {
			fmt.Println("\nDisconnecting...")
		}
	})
}

// cmdCheckDevice tells whether the device carries a cryptkey (used by the udev rule): exit status 0
// if it does.
func cmdCheckDevice() {
	if len(os.Args) < 3 {
		os.Exit(2)
	}
	ok, err := usb.CheckDevice(os.Args[2])
	if err != nil || !ok {
		os.Exit(1)
	}
	os.Exit(0)
}

func cmdDisconnect() {
	mountPoint := getMountPoint()
	if err := sshconn.Umount(mountPoint); err != nil {
		fmt.Fprintf(os.Stderr, "Local umount: %v\n", err)
	} else {
		fmt.Println("✓ Disconnected locally.")
	}
}

func cmdStatus() {
	if serverConfigured() {
		fmt.Printf("Server:      %s\n", serverURL())
	} else {
		fmt.Println("Server:      not set (cryptclient setup asks for it)") // not the placeholder
	}
	fmt.Printf("Mount point: %s\n", getMountPoint())
	mountPoint := getMountPoint()
	if info, err := os.Stat(mountPoint); err == nil && info.IsDir() {
		fmt.Println("Local mount: directory exists")
	} else {
		fmt.Println("Local mount: not found")
	}
	if dev, err := findStick(); err == nil {
		printEscrowStatus(getUSBMountPath(dev))
	}
}

func cmdInitUSB() {
	dev := chooseDevice()
	pw := promptNewPassword("Set password for this USB key: ")
	pubKey, pem, err := writeStick(dev, pw)
	if err != nil {
		fatal("%v", err)
	}
	for i := range pem {
		pem[i] = 0
	}

	fmt.Println("\n✅ USB stick initialized successfully!")
	fmt.Println("\nYour SSH public key (register with the server):")
	fmt.Println(string(pubKey))
}

// chooseDevice lists the USB devices and asks which one to use. It exits if there is none.
func chooseDevice() usb.Device {
	fmt.Println("⚠️  USB Stick Initialization")
	fmt.Println("This puts a new key on the selected stick (in its hidden .secdisk folder).")
	fmt.Println("Make sure you select the correct device!")
	fmt.Println()

	candidates, err := listUSBCandidates()
	if err != nil || len(candidates) == 0 {
		fatal("No USB devices found: %v", err)
	}

	fmt.Println("Available devices:")
	for i, dev := range candidates {
		fmt.Printf("  [%d] %s\n", i+1, dev.Path)
	}

	choice, err := strconv.Atoi(promptLine("\nSelect device number: "))
	if err != nil || choice < 1 || choice > len(candidates) {
		fatal("Invalid selection.")
	}
	selectedDev := candidates[choice-1]
	if err := usb.CheckWritable(selectedDev.Path); err != nil {
		fatal("%v", err)
	}

	if !isYes(promptLine(fmt.Sprintf("\nWARNING: Writing to %s. Continue? (yes/no): ", selectedDev.Path))) {
		fmt.Println("Aborted.")
		os.Exit(0)
	}
	return selectedDev
}

// writeStick puts a fresh key, protected by password, on the device together with the server's TLS
// pin and the serial binding. It returns the public key and the unencrypted private key (the caller
// wipes it).
func writeStick(dev usb.Device, password string) (pubKey, pem []byte, err error) {
	// The key goes into the .secdisk folder on the stick's own file system, the same on Linux and
	// Windows, so the stick works on both. A stick without a usable file system is erased first (Linux).
	if err := usb.PrepareFiles(dev.Path); err != nil {
		if runtime.GOOS != "linux" || !errors.Is(err, usb.ErrNoFileSystem) {
			return nil, nil, fmt.Errorf("this stick cannot be used as it is:\n%v", err)
		}
		if os.Geteuid() != 0 {
			return nil, nil, fmt.Errorf("the stick has no file system that can be opened, so it has to be erased and " +
				"formatted. Format it (for example in Disks) and run this again, or let this command do it:\n" +
				"    sudo cryptclient init-usb")
		}
		if err := offerErase(dev, "The stick has no file system that can be opened."); err != nil {
			return nil, nil, err
		}
		if err := usb.PrepareFiles(dev.Path); err != nil {
			return nil, nil, fmt.Errorf("after erasing, the stick's file system could not be opened: %v\n"+
				"Plug the stick in again and run the command once more.", err)
		}
	}

	fmt.Println("Generating SSH key pair...")
	pubKey, privKeyPEM, err := generateSSHKeyPair()
	if err != nil {
		return nil, nil, fmt.Errorf("key generation failed: %v", err)
	}

	encrypted, err := crypto.EncryptKey(privKeyPEM, password)
	if err != nil {
		return nil, nil, fmt.Errorf("key encryption failed: %v", err)
	}

	fmt.Printf("Writing key to %s...\n", dev.Path)
	if err := usb.WriteEncryptedKey(dev.Path, encrypted); err != nil {
		return nil, nil, fmt.Errorf("writing to USB failed: %v", err)
	}

	// Store the server's TLS certificate pin
	pinServerCert(serverURL(), getUSBMountPath(dev.Path))
	bindStickToServer(getUSBMountPath(dev.Path))

	// Bind to the stick's serial number
	serial, err := usb.GetSerial(dev.Path)
	if err != nil {
		fmt.Printf("⚠️  Could not bind serial number: %v\n", err)
	} else {
		if err := usb.WriteSerialBinding(dev.Path, serial); err != nil {
			fmt.Printf("⚠️  Could not write serial binding: %v\n", err)
		} else {
			fmt.Printf("✓ Key bound to device serial: %s\n", serial)
		}
	}
	return pubKey, privKeyPEM, nil
}

// offerErase asks whether the stick may be erased and given a fresh layout, and does it. The user
// confirms by typing the device's name, since a wrong device loses everything on it.
func offerErase(dev usb.Device, reason string) error {
	name := filepath.Base(dev.Path)
	fmt.Printf("\n%s\n\nThe stick can be erased and set up for CryptStorage: one FAT32 partition for your files and\n", reason)
	fmt.Printf("the key. EVERYTHING ON %s (%s) WILL BE LOST.\n", dev.Path, describeDevice(name))
	if promptLine(fmt.Sprintf("Type %s to erase it, anything else to stop: ", name)) != name {
		return fmt.Errorf("stopped; nothing was written")
	}
	fmt.Printf("Erasing %s...\n", dev.Path)
	if err := usb.EraseStick(dev.Path); err != nil {
		return err
	}
	fmt.Println("✓ Stick erased and formatted (FAT32, label CRYPTSTORE).")
	fmt.Println("  When this is done, remove the stick and plug it in again so that your desktop opens it for you.")
	return nil
}

// describeDevice gives the size and model of a Linux block device, so the user can recognise it.
func describeDevice(name string) string {
	var parts []string
	if b, err := os.ReadFile(filepath.Join("/sys/block", name, "size")); err == nil {
		if sectors, err := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64); err == nil {
			parts = append(parts, fmt.Sprintf("%.1f GB", float64(sectors*512)/1e9))
		}
	}
	for _, f := range []string{"device/vendor", "device/model"} {
		if b, err := os.ReadFile(filepath.Join("/sys/block", name, f)); err == nil && strings.TrimSpace(string(b)) != "" {
			parts = append(parts, strings.TrimSpace(string(b)))
		}
	}
	if len(parts) == 0 {
		return "unknown device"
	}
	return strings.Join(parts, ", ")
}

// --- Helpers ---

func fatal(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "Error: "+format+"\n", args...)
	os.Exit(1)
}

func serverURL() string {
	if s := os.Getenv("CRYPTSTORAGE_SERVER"); s != "" {
		return s
	}
	return defaultServer
}

// probeServer checks that the address in CRYPTSTORAGE_SERVER answers like a CryptStorage API.
func probeServer() error {
	_, err := newAPI("").ServerInfo()
	return err
}

// serverHost returns the bare hostname of CRYPTSTORAGE_SERVER. The URL may carry
// a port or a path (e.g. https://example.com/api); the SSH connection needs only
// the host.
func serverHost() string {
	s := serverURL()
	if !strings.Contains(s, "://") {
		s = "https://" + s
	}
	u, err := url.Parse(s)
	if err != nil || u.Hostname() == "" {
		return s
	}
	return u.Hostname()
}

func getMountPoint() string {
	if m := os.Getenv("CRYPTSTORAGE_MOUNT"); m != "" {
		return m
	}
	if runtime.GOOS == "windows" {
		// a drive letter is what a beginner expects to find in Explorer
		for l := 'S'; l <= 'Z'; l++ {
			d := string(l) + ":"
			if _, err := os.Stat(d + `\`); err != nil {
				return d
			}
		}
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, "cryptstorage")
}

func isDriveLetter(p string) bool {
	return runtime.GOOS == "windows" && len(p) == 2 && p[1] == ':'
}

func getUSBMountPath(devicePath string) string {
	if runtime.GOOS == "windows" {
		return strings.TrimSuffix(usb.WindowsMountRoot(devicePath), `\`)
	}
	// "" when the stick's file system is not mounted: never a shared temporary directory
	return usb.MountPath(devicePath)
}

func listUSBCandidates() ([]usb.Device, error) {
	if runtime.GOOS == "windows" {
		return usb.ListRemovable()
	}
	if runtime.GOOS == "linux" {
		return listLinuxRemovable()
	}
	entries, _ := os.ReadDir("/dev")
	var devs []usb.Device
	for _, e := range entries {
		n := e.Name()
		if len(n) == 3 && (n[:2] == "sd" || n[:2] == "vd") {
			devs = append(devs, usb.Device{Path: "/dev/" + n, Label: n})
		}
	}
	return devs, nil
}

func listLinuxRemovable() ([]usb.Device, error) {
	entries, err := os.ReadDir("/sys/block")
	if err != nil {
		return nil, err
	}
	var devs []usb.Device
	for _, e := range entries {
		removablePath := filepath.Join("/sys/block", e.Name(), "removable")
		data, err := os.ReadFile(removablePath)
		if err != nil {
			continue
		}
		if len(data) > 0 && data[0] == '1' {
			devs = append(devs, usb.Device{
				Path:  "/dev/" + e.Name(),
				Label: e.Name() + " (removable)",
			})
		}
	}
	return devs, nil
}

// bindStickToServer notes on a freshly keyed stick the server it is now for. What the stick remembered
// about another server it belonged to before (its escrow setting, its SSH host keys) is dropped with it.
func bindStickToServer(mount string) {
	if mount == "" {
		return
	}
	rec := stickserver.Record{URL: serverURL()}
	if info, err := newAPI(mount).ServerInfo(); err == nil {
		rec.ServerID = info.ServerID
	}
	if old, _ := stickserver.Load(mount); old != nil && stickserver.Check(old, rec.URL, rec.ServerID) != nil {
		for _, f := range []string{escrowcheck.File, sshconn.HostKeyFile} {
			_ = os.Remove(filepath.Join(mount, f))
		}
	}
	if err := stickserver.Save(mount, rec); err != nil {
		fmt.Printf("⚠️  Could not note the server on the stick: %v (connecting does it later)\n", err)
	}
}

// Cert pin file name on the stick's FAT32 partition
const certPinFile = "cryptstorage.certpin"

// loadCertPin loads the stored TLS certificate SHA256 fingerprint from the stick's FAT32 partition.
// Returns an empty string if the file is not found or the environment variable is set.
// pinServerCert saves the server's TLS public-key pin on the stick.
func pinServerCert(server, usbMountPath string) {
	if strings.HasPrefix(strings.ToLower(server), "http://") {
		// nothing to pin: say what that means instead of a warning about a certificate that cannot exist
		fmt.Println("ℹ️  The server uses plain http, without TLS: fine for a test server on your own network,")
		fmt.Println("   never for real data. No certificate pin is saved.")
		return
	}
	fmt.Printf("Fetching TLS certificate from %s...\n", server)
	fp, err := apiclient.GetPinnedFingerprint(server)
	if err != nil {
		fmt.Printf("⚠️  Could not fetch TLS certificate: %v\n", err)
		fmt.Println("   Add CRYPTSTORAGE_CERT_PIN manually to skip.")
		return
	}
	if err := saveCertPin(usbMountPath, fp); err != nil {
		fmt.Printf("⚠️  Could not save cert pin: %v\n", err)
		return
	}
	fmt.Printf("✓ TLS public key pinned: %s\n", fp)
	fmt.Println("  The pin follows the server's key, not the certificate: it keeps working when the")
	fmt.Println("  certificate is renewed with the same key. Add a second pin on its own line in")
	fmt.Printf("  %s (e.g. your CA's intermediate) so a key change does not lock you out.\n", certPinFile)
}

func loadCertPin(usbMountPath string) string {
	// The environment variable overrides the value on the stick (development/testing)
	if pin := os.Getenv("CRYPTSTORAGE_CERT_PIN"); pin != "" {
		return pin
	}
	if usbMountPath == "" {
		return ""
	}
	data, err := os.ReadFile(filepath.Join(usbMountPath, certPinFile))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// saveCertPin stores the TLS certificate SHA256 fingerprint on the stick's FAT32 partition.
func saveCertPin(usbMountPath, fingerprint string) error {
	if usbMountPath == "" {
		return fmt.Errorf("USB mount path not found")
	}
	return os.WriteFile(
		filepath.Join(usbMountPath, certPinFile),
		[]byte(fingerprint+"\n"),
		0600,
	)
}

// cmdUpgradeKey re-encrypts the key on the stick with the current format (Argon2id).
// It writes a backup of the old blob to the stick's file system first and checks that
// the new blob decrypts to the same key before and after writing.
func cmdUpgradeKey() {
	devicePath := os.Getenv("CRYPTCLIENT_DEVICE")
	if devicePath == "" {
		dev, err := usb.FindCryptDevice()
		if err != nil {
			fatal("USB device not found: %v\nPlease insert your cryptkey USB stick.", err)
		}
		devicePath = dev.Path
	}

	blob, err := usb.ReadEncryptedKey(devicePath)
	if err != nil {
		fatal("Could not read key from USB: %v", err)
	}
	if !crypto.NeedsUpgrade(blob) {
		fmt.Println("✓ The key on this stick already uses the current format.")
		return
	}

	fmt.Print("Password: ")
	pw, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	if err != nil {
		fatal("Could not read password: %v", err)
	}
	pem, err := crypto.DecryptKey(blob, string(pw))
	if err != nil {
		fatal("Wrong password or corrupted key: %v", err)
	}
	defer func() {
		for i := range pem {
			pem[i] = 0
		}
	}()

	upgraded, err := crypto.EncryptKey(pem, string(pw))
	if err != nil {
		fatal("Key encryption failed: %v", err)
	}
	if check, err := crypto.DecryptKey(upgraded, string(pw)); err != nil || !bytes.Equal(check, pem) {
		fatal("The upgraded key did not decrypt to the same key; nothing was written.")
	}

	mount := getUSBMountPath(devicePath)
	if mount == "" {
		fatal("Cannot find the stick's file system to keep a backup of the old key file.\nNothing was written.")
	}
	backup := filepath.Join(mount, "cryptstorage-key-backup.bin")
	if err := os.WriteFile(backup, blob, 0600); err != nil {
		fatal("Could not write the backup (%v). Nothing was written to the key area.", err)
	}

	if err := usb.WriteEncryptedKey(devicePath, upgraded); err != nil {
		fatal("Writing the upgraded key failed: %v\nThe old key file is saved in %s", err, backup)
	}
	if back, err := usb.ReadEncryptedKey(devicePath); err != nil || !bytes.Equal(back, upgraded) {
		fatal("The key read back from the stick differs from what was written.\nRestore the old one from %s.", backup)
	}

	fmt.Println("✓ Key upgraded to Argon2id.")
	fmt.Printf("  Backup of the old key file: %s\n", backup)
	fmt.Println("  It is protected with the old, weaker format. Check that connecting works, then delete it.")
}
