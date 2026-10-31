package main

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"cryptclient/e2ee"
	"cryptclient/setup"
	"cryptclient/usb"
)

// cmdSetup is the guided first-time setup for end-to-end encrypted servers.
func cmdSetup() {
	refuseElevated()
	if runtime.GOOS == "windows" {
		if err := installDeps(false, false); err != nil {
			fmt.Println("Error:", err)
			os.Exit(1)
		}
	}
	if err := askServer(promptLine, probeServer); err != nil {
		fmt.Println("Error:", err)
		os.Exit(1)
	}
	res, err := setup.Run(setup.Env{
		UI:       consoleUI{},
		Stick:    &realStick{},
		API:      newAPI,
		HostKeys: hostKeys,
		Trust:    confirmHostKey,
		Missing:  missingRequirements,
	})
	if err != nil {
		os.Exit(1)
	}
	// connect and the tray offer it, and the installer knows from it that setup was done
	rememberUsername(res.Username)
	// the installer starts only this setup, not the tray as well; the padlock comes after it
	startTrayAfterSetup()
}

type consoleUI struct{}

func (consoleUI) Say(format string, args ...any) { fmt.Printf(format+"\n", args...) }
func (consoleUI) Ask(label string) string        { return promptLine(label) }
func (consoleUI) AskSecret(label string) string  { return promptPassword(label) }
func (consoleUI) Confirm(label string) bool {
	return isYes(promptLine(label))
}

// realStick is the physical stick: found by its marker, prepared by raw writes.
type realStick struct {
	dev *usb.Device
}

func (s *realStick) Present() bool {
	if p := os.Getenv("CRYPTCLIENT_DEVICE"); p != "" {
		s.dev = &usb.Device{Path: p}
		return true
	}
	dev, err := usb.FindCryptDevice()
	if err != nil {
		return false
	}
	s.dev = dev
	return true
}

func (s *realStick) ReadKey() ([]byte, error) {
	if err := usb.VerifySerialBinding(s.dev.Path); err != nil {
		return nil, err
	}
	return usb.ReadEncryptedKey(s.dev.Path)
}

func (s *realStick) Prepare(password string, confirmed bool) ([]byte, string, error) {
	var dev usb.Device
	if s.dev != nil {
		if !confirmed {
			fmt.Printf("A prepared stick was found (%s), but it does not open with this password.\n", s.dev.Path)
			fmt.Print("Prepare it again? The old key on it is erased. (yes/no): ")
			if !isYes(readLine()) {
				return nil, "", setup.ErrAborted
			}
		}
		dev = *s.dev
	} else {
		dev = chooseDevice()
	}
	pub, pem, err := writeStick(dev, password)
	if err != nil {
		return nil, "", err
	}
	s.dev = &dev
	return pem, strings.TrimSpace(string(pub)), nil
}

func (s *realStick) WriteKey(old, blob []byte) error {
	return writeKeyChecked(s.dev.Path, old, blob)
}

func (s *realStick) MountPath() string {
	if s.dev == nil {
		return ""
	}
	return getUSBMountPath(s.dev.Path)
}

// missingRequirements lists what has to be installed, in words a beginner can follow.
func missingRequirements() []string {
	var missing []string
	have := func(name string) bool { _, err := exec.LookPath(name); return err == nil }
	switch runtime.GOOS {
	case "linux":
		if !have("gocryptfs") || !have("sshfs") {
			missing = append(missing, "gocryptfs and sshfs. On Ubuntu or Debian: sudo apt install gocryptfs sshfs")
		}
	case "darwin":
		if !have("gocryptfs") || !have("sshfs") {
			missing = append(missing, "macFUSE, gocryptfs and sshfs (for example with Homebrew)")
		}
	case "windows":
		if !e2ee.CppcryptfsInstalled() {
			missing = append(missing, "cppcryptfs (unlocks the encrypted files) - https://github.com/bailey27/cppcryptfs/releases")
		}
		if !e2ee.DokanInstalled() {
			missing = append(missing, "the Dokan driver that cppcryptfs needs - https://github.com/dokan-dev/dokany/releases")
		}
		if _, err := os.Stat(`C:\Program Files\SSHFS-Win`); err != nil {
			missing = append(missing, "SSHFS-Win and WinFsp (connect to the server) - https://github.com/winfsp/sshfs-win/releases")
		}
	}
	return missing
}
