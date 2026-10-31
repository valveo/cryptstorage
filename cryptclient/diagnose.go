package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"cryptclient/appdir"
	"cryptclient/diskenc"
	"cryptclient/e2ee"
	"cryptclient/stickserver"
	"cryptclient/usb"
)

// cmdDiagnose prints what this machine has and lacks, in one screen that can be pasted into a bug
// report. It changes nothing and reads no key. Its main use is bringing up a new platform (Windows).
func cmdDiagnose() {
	fmt.Printf("cryptclient %s on %s/%s\n\n", appVersion(), runtime.GOOS, runtime.GOARCH)

	fmt.Println("Programs")
	tools := []string{"sshfs", "gocryptfs", "fusermount", "ssh"}
	if runtime.GOOS == "windows" {
		tools = []string{"ssh"} // the Windows pieces are checked below, they are not on PATH
	}
	for _, name := range tools {
		if p, err := exec.LookPath(name); err == nil {
			fmt.Printf("  found    %-12s %s\n", name, p)
		} else {
			fmt.Printf("  missing  %-12s\n", name)
		}
	}
	if runtime.GOOS == "windows" {
		for _, p := range []string{`C:\Program Files (x86)\WinFsp`, `C:\Program Files\WinFsp`, `C:\Program Files\SSHFS-Win`} {
			if _, err := os.Stat(p); err == nil {
				fmt.Printf("  found    %s\n", p)
			} else {
				fmt.Printf("  missing  %s\n", p)
			}
		}
	}

	if runtime.GOOS == "windows" {
		fmt.Printf("  %-8s cppcryptfs\n", map[bool]string{true: "found", false: "missing"}[e2ee.CppcryptfsInstalled()])
		fmt.Printf("  %-8s Dokan driver (dokan2.dll)\n", map[bool]string{true: "found", false: "missing"}[e2ee.DokanInstalled()])
	}

	fmt.Println("\nServer")
	if !serverConfigured() {
		fmt.Println("  address  not set (cryptclient setup asks for it)")
	} else {
		fmt.Printf("  address  %s\n", serverURL())
		fmt.Printf("  from     %s\n", settingSource("CRYPTSTORAGE_SERVER"))
		if info, err := newAPI("").ServerInfo(); err != nil {
			fmt.Printf("  cannot reach it: %v\n", err)
		} else {
			fmt.Printf("  version  %s\n", info.Version)
			fmt.Printf("  mode     %s, recovery policy %s\n", info.StorageMode, info.RecoveryPolicy)
		}
	}

	if old := legacySettings(); old != "" {
		fmt.Printf("  note     an older version's folder is still there: %s (not read; remove it if it is not needed)\n", old)
	}

	fmt.Println("\nUSB")
	if cands, err := listUSBCandidates(); err != nil {
		fmt.Printf("  listing devices failed: %v\n", err)
	} else if len(cands) == 0 {
		fmt.Println("  no removable devices found")
	} else {
		for _, d := range cands {
			fmt.Printf("  device   %s\n", d.Path)
		}
	}
	if dev, err := usb.FindCryptDevice(); err != nil {
		fmt.Printf("  stick    none prepared (%v)\n", err)
	} else {
		fmt.Printf("  stick    prepared stick at %s\n", dev.Path)
		diagnoseStickServer(getUSBMountPath(dev.Path))
	}
	fmt.Println("\nSynchronised folder")
	if dir := syncDir(); dir == "" {
		fmt.Println("  off (connect --sync or CRYPTCLIENT_SYNC_DIR)")
	} else {
		r := diskenc.Check(dir)
		fmt.Printf("  folder   %s\n  disk     %s (%s)\n", dir, r.State, r.Detail)
	}
	fmt.Println("\nSetup in this state:", func() string {
		if m := missingRequirements(); len(m) > 0 {
			return "blocked: " + m[0]
		}
		return "can run (cryptclient setup)"
	}())
}

// diagnoseStickServer shows the server the stick belongs to next to the configured one.
func diagnoseStickServer(mount string) {
	rec, err := stickserver.Load(mount)
	switch {
	case mount == "":
		fmt.Println("  server   unknown (the stick's file system is not mounted)")
		return
	case err != nil:
		fmt.Printf("  server   %v\n", err)
		return
	case rec == nil:
		fmt.Println("  server   not noted yet (the next connect notes it)")
		return
	}
	fmt.Printf("  server   %s\n", rec.URL)
	if rec.ServerID != "" {
		fmt.Printf("  id       %s\n", rec.ServerID)
	}
	for _, fp := range rec.HostKeys {
		fmt.Printf("  host key %s\n", fp)
	}
	if !serverConfigured() {
		return
	}
	id := ""
	if info, err := newAPI(mount).ServerInfo(); err == nil {
		id = info.ServerID
	}
	if err := stickserver.Check(rec, serverURL(), id); err != nil {
		fmt.Println("  WARNING  the stick belongs to another server than the one set above")
	} else {
		fmt.Println("  ok       the stick belongs to the server set above")
	}
}

// settingSource tells where a setting came from: the environment wins over the settings file, so an old
// variable (in .bashrc, a service unit) can hide what the file says.
func settingSource(key string) string {
	if startEnv[key] {
		return "the environment variable " + key + " (it wins over the settings file)"
	}
	if p := envFilePath(); p != "" {
		return p
	}
	return "nowhere (no settings file)"
}

// legacySettings returns the folder an older version (secdisk) made, when it still exists next to the
// one now used: its settings are no longer read, which can be surprising after an update.
func legacySettings() string {
	p := envFilePath()
	if p == "" {
		return ""
	}
	dir := filepath.Dir(p)
	if filepath.Base(dir) != appdir.Name {
		return ""
	}
	old := filepath.Join(filepath.Dir(dir), appdir.Legacy)
	if fi, err := os.Stat(old); err == nil && fi.IsDir() {
		return old
	}
	return ""
}
