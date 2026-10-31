package main

import (
	"fmt"

	"cryptclient/apiclient"
	"cryptclient/escrowcheck"
)

// Escrow on the client side: the settings the user accepted are kept on the stick, and a
// change on the server is reported here, where the operator cannot hide it.

func escrowConsent(a asker) func(fp string) bool {
	return func(fp string) bool {
		// one question with the whole text: in the tray it is a single message box
		return a.Confirm("\n" + escrowcheck.ConsentText(fp) + "\n\nDo you agree that your organisation keeps this copy?")
	}
}

// rememberEscrow stores what the user has now seen and accepted. A failure is only a warning: the
// next connection will then ask again.
func rememberEscrow(usbMount string, info *apiclient.ServerInfo) {
	rec, err := escrowcheck.FromServer(info)
	if err == nil {
		err = escrowcheck.Save(usbMount, rec)
	}
	if err != nil {
		fmt.Printf("Warning: could not remember the escrow setting on the stick: %v\n", err)
	}
}

// checkEscrow compares the server's escrow settings with the ones accepted on this stick. The first
// time (no record yet) the current ones are recorded. A change is shown and, if the user accepts
// it, recorded; otherwise the warning comes back on every connection. Nothing is ever sealed here:
// connecting does not expose the storage key, whatever the server says.
func checkEscrow(a asker, usbMount string, info *apiclient.ServerInfo) error {
	now, err := escrowcheck.FromServer(info)
	if err != nil {
		return err
	}
	accepted, found, err := escrowcheck.Load(usbMount)
	if err != nil {
		fmt.Printf("Warning: %v\n", err)
	}
	if !found {
		if usbMount != "" {
			rememberEscrow(usbMount, info)
		}
		return nil
	}
	change := escrowcheck.Change(accepted, now)
	if change == "" {
		return nil
	}
	question := "⚠️  ESCROW SETTING CHANGED ON THE SERVER\n" + change +
		"\nNothing has been sealed for you. Ask your administrator why it changed." +
		"\nAccept the new setting? (no = warn again next time)"
	if a.Confirm(question) {
		rememberEscrow(usbMount, info)
	}
	return nil
}

// printEscrowStatus shows the escrow setting recorded on the stick (for `cryptclient status`).
func printEscrowStatus(usbMount string) {
	rec, found, err := escrowcheck.Load(usbMount)
	switch {
	case err != nil:
		fmt.Printf("Escrow:      %v\n", err)
	case !found:
		fmt.Println("Escrow:      not recorded on this stick yet (connect once)")
	default:
		fmt.Printf("Escrow:      %s\n", rec.Describe())
	}
}
