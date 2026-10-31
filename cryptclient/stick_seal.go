package main

// Sealing the stick's key with the server's stick secret: see package stickkey.

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"cryptclient/apiclient"
	"cryptclient/stickkey"
	"cryptclient/stickserver"
	"cryptclient/usb"
)

// checkStickServer stops when the stick belongs to another server than the one this computer is set to:
// using it there would at best fail and at worst seal its key to the wrong server. info is the
// configured server's /server-info.
func checkStickServer(usbMount string, info *apiclient.ServerInfo) error {
	rec, err := stickserver.Load(usbMount)
	if err != nil {
		return fmt.Errorf("Could not read which server the stick belongs to: %w", err)
	}
	return stickserver.Check(rec, serverURL(), info.ServerID)
}

// checkStickServerEarly is checkStickServer before the password is asked, so that a stick of another
// server is not even unlocked. A server that does not answer is left for the connect to report.
func checkStickServerEarly(devicePath string) error {
	mount := getUSBMountPath(devicePath)
	if mount == "" {
		return nil
	}
	info, err := newAPI(mount).ServerInfo()
	if err != nil {
		return nil
	}
	return checkStickServer(mount, info)
}

// rememberStickServer records on the stick the server it just worked with: a stick from an older version
// gets its first record, and a server that moved to a new address is remembered there.
func rememberStickServer(usbMount string, info *apiclient.ServerInfo, hostKeys []string, say func(string)) {
	if usbMount == "" {
		return
	}
	rec, _ := stickserver.Load(usbMount)
	next, changed := stickserver.Updated(rec, serverURL(), info.ServerID, hostKeys)
	if !changed {
		return
	}
	if err := stickserver.Save(usbMount, next); err != nil {
		say("Could not note on the stick which server it belongs to (" + err.Error() + "); the next connect tries again.")
		return
	}
	if rec != nil && !stickserver.SameURL(rec.URL, next.URL) {
		say("The stick now remembers the server's new address " + next.URL + ".")
	}
}

// open decrypts a sealed key after the login; a key in an older format was opened by openStick already.
func (s *stick) open(a asker, api *apiclient.Client) error {
	if s.pem != nil {
		return nil
	}
	pem, err := stickkey.Open(api, s.blob, s.password)
	if errors.Is(err, apiclient.ErrStickLocked) {
		// locked in the web UI, e.g. reported lost: whoever is here has the stick, the password and
		// the second factor, which is what unlocking needs
		if !a.Confirm("This stick is locked in your account: it was reported lost, or its removal was " +
			"requested. Unlock it and use it again?") {
			return errors.New("The stick is locked. Connect with it again to unlock it.")
		}
		id, _ := stickkey.ID(s.blob)
		if err = api.UnlockStick(id); err != nil {
			return fmt.Errorf("Could not unlock the stick: %w", err)
		}
		pem, err = stickkey.Open(api, s.blob, s.password)
	}
	switch {
	case errors.Is(err, apiclient.ErrStickRevoked):
		return errors.New("This stick does not belong to this account, or it was removed from it, so its key " +
			"cannot be opened.\nCheck the username. If the stick was removed after it was lost, prepare it anew: " +
			"cryptclient init-usb, then cryptclient setup.")
	case err != nil && !errors.Is(err, apiclient.ErrNoStickSecrets):
		var apiErr *apiclient.APIError
		if errors.As(err, &apiErr) {
			return fmt.Errorf("Could not get the stick's secret from the server: %w", err)
		}
		return errWrongPassword
	case err != nil:
		return errors.New("The key on this stick needs a stick secret, and this server does not offer them.")
	}
	s.pem = pem
	return nil
}

// seal moves a key in an older format to the sealed one, so that the stick can no longer be attacked
// offline. Call it only after an SFTP login with the stick's key worked: that is what shows the server is the
// stick's own (a tray still set to an old server once sealed a stick there). It is best effort: if anything fails, the stick keeps its old key and the next connect tries
// again. say gets what the user should know.
func (s *stick) seal(api *apiclient.Client, say func(string)) {
	if s.pem == nil || stickkey.Sealed(s.blob) {
		return
	}
	host, _ := os.Hostname()
	if host == "" {
		host = "stick"
	}
	blob, err := stickkey.Seal(api, s.pem, s.password, host)
	if errors.Is(err, apiclient.ErrNoStickSecrets) {
		return // an older server: the key stays as it is
	}
	if err == nil {
		err = writeKeyChecked(s.device, s.blob, blob)
	}
	if err != nil {
		say("The key on your stick could not be protected with the server's stick secret yet (" + err.Error() +
			"). It still works; the next connect tries again.")
		return
	}
	s.blob = blob
	// a copy kept by upgrade-key is protected by the password alone: it would undo the point
	if s.usbMount != "" {
		backup := filepath.Join(s.usbMount, "cryptstorage-key-backup.bin")
		if _, err := os.Stat(backup); err == nil {
			if err := os.Remove(backup); err != nil {
				say("Delete " + backup + ": it is an older copy of your key that can be attacked offline.")
			}
		}
	}
	say("The key on your stick is now also protected by the server: a lost or copied stick cannot be " +
		"attacked offline any more.")
}

// writeKeyChecked writes blob and reads it back; on a mismatch it puts the old blob back.
func writeKeyChecked(device string, old, blob []byte) error {
	if err := usb.WriteEncryptedKey(device, blob); err != nil {
		return err
	}
	if back, err := usb.ReadEncryptedKey(device); err == nil && bytes.Equal(back, blob) {
		return nil
	}
	if err := usb.WriteEncryptedKey(device, old); err != nil {
		return fmt.Errorf("the new key did not read back, and putting the old one back failed too: %w", err)
	}
	return errors.New("the new key did not read back the same; the old one is back")
}
