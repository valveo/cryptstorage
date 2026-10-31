package diskenc

import (
	"os/exec"
	"strings"
)

// Advice names the encryption to turn on.
func Advice() string { return "FileVault (System Settings, Privacy & Security)" }

// check asks fdesetup, which reports the startup disk. Untested on macOS.
func check(string) Result {
	out, err := exec.Command("fdesetup", "status").Output()
	switch s := string(out); {
	case err != nil:
		return Result{Unknown, "could not ask about FileVault"}
	case strings.Contains(s, "FileVault is On"):
		return Result{Encrypted, "FileVault on"}
	case strings.Contains(s, "FileVault is Off"):
		return Result{NotEncrypted, "FileVault off"}
	}
	return Result{Unknown, "FileVault state unknown"}
}
