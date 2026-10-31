package main

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"cryptclient/deps"
)

// cmdInstallDeps installs the Windows components the client needs.
//
//	install-deps          ask, install what is missing (asks Windows for permission once if needed)
//	install-deps --yes    the same without the question (used by the installer)
//	install-deps --msi    only the drivers; needs an administrator process (the program starts this itself)
//	--log FILE            write the output to FILE instead (the elevated window closes, so the parent shows it)
func cmdInstallDeps() {
	args := os.Args[2:]
	has := func(f string) bool {
		for _, a := range args {
			if a == f {
				return true
			}
		}
		return false
	}
	for i, a := range args {
		if a == "--log" && i+1 < len(args) {
			if f, err := os.Create(args[i+1]); err == nil {
				defer f.Close()
				os.Stdout = f
			}
		}
	}
	if err := installDeps(has("--yes"), has("--msi")); err != nil {
		fmt.Println("Error:", err)
		os.Stdout.Close()
		os.Exit(1)
	}
}

func splitByKind(cs []deps.Component) (msi, exe []deps.Component) {
	for _, c := range cs {
		if c.Kind == deps.MSI {
			msi = append(msi, c)
		} else {
			exe = append(exe, c)
		}
	}
	return
}

func say(format string, a ...any) { fmt.Printf(format+"\n", a...) }

// installDeps returns nil when everything needed is there afterwards (or a restart is pending, which it reports).
func installDeps(yes, msiOnly bool) error {
	missing := deps.Missing()
	msi, exe := splitByKind(missing)
	if msiOnly {
		return installShared(msi)
	}
	if len(missing) == 0 {
		say("Everything the client needs is already installed.")
		return nil
	}
	say("The client needs these programs, which are not installed:")
	for _, c := range missing {
		say("  - %s: %s", c.Name, c.Why)
	}
	say("They are downloaded from their official release pages and checked against a fixed checksum before they are installed.")
	if len(msi) > 0 && !deps.IsAdmin() {
		say("Windows will ask for your permission once, because drivers are installed.")
	}
	if !yes && !isYes(promptLine("Install them now? (yes/no): ")) {
		return errors.New("not installed; the client cannot work without them")
	}
	if len(exe) > 0 {
		if err := deps.Install(exe, say); err != nil {
			return err
		}
	}
	if len(msi) > 0 {
		if deps.IsAdmin() {
			return reportReboot(deps.Install(msi, say))
		}
		self, err := os.Executable()
		if err != nil {
			return err
		}
		if err := runElevatedShowingLog(self); err != nil {
			return err
		}
	}
	if still := deps.Missing(); len(still) > 0 {
		names := make([]string, len(still))
		for i, c := range still {
			names[i] = c.Name
		}
		return fmt.Errorf("these are still missing: %s. If Windows asked for a restart, restart and run the command again", strings.Join(names, ", "))
	}
	say("Done.")
	return nil
}

// installShared is the administrator part (install-deps --msi): the drivers, and when the client is
// installed under Program Files also cppcryptfs and rclone next to it, out of the user profile where
// antivirus heuristics quarantine them. rclone is only needed for the synchronised folder, so
// failing to fetch it is not fatal: it is then fetched into the user's folder on first use.
// A copy the user already has in their own folder does not count: the shared folder gets its own.
func installShared(msi []deps.Component) error {
	shared := deps.SharedDir()
	if shared == "" || !deps.IsAdmin() {
		return reportReboot(deps.Install(msi, say))
	}
	var exe []deps.Component
	for _, c := range deps.All() {
		if c.Kind == deps.Exe && !c.InDir(shared) {
			exe = append(exe, c)
		}
	}
	if err := deps.Install(exe, say); err != nil {
		return err
	}
	if !deps.RcloneInDir(shared) {
		if _, err := deps.InstallRclone(say); err != nil {
			say("rclone was not installed (%v); it is fetched when the synchronised folder is first used.", err)
		}
	}
	return reportReboot(deps.Install(msi, say))
}

// runElevatedShowingLog runs install-deps --msi as administrator and prints what it wrote, so a failure
// in the elevated window (which closes when it ends) is not lost.
func runElevatedShowingLog(self string) error {
	log, err := os.CreateTemp("", "cryptstorage-install-*.log")
	if err != nil {
		return err
	}
	path := log.Name()
	log.Close()
	defer os.Remove(path)
	err = deps.RunElevated(self, "install-deps", "--msi", "--log", path)
	if out, rerr := os.ReadFile(path); rerr == nil && len(out) > 0 {
		say("Output of the administrator part:")
		for _, l := range strings.Split(strings.TrimRight(strings.ReplaceAll(string(out), "\r\n", "\n"), "\n"), "\n") {
			say("  %s", l)
		}
	} else if err != nil {
		say("The administrator part wrote nothing; the permission was probably refused.")
	}
	return err
}

func reportReboot(err error) error {
	if errors.Is(err, deps.RebootRequired) {
		say("Installed. Windows asks for a restart to finish; restart, then run the client again.")
		return nil
	}
	return err
}
