// Package nowindow starts helper programs (PowerShell, rclone, cppcryptfsctl, ...) without a console
// window of their own. The graphical client (CryptStorage.exe, the tray) has no console, and Windows gives
// every console program it starts a new, visible one: each status check would flash a black window.
// Elsewhere these are plain exec.Command and exec.CommandContext.
package nowindow

import (
	"context"
	"os/exec"
)

// Command is exec.Command, without a console window on Windows.
func Command(name string, args ...string) *exec.Cmd {
	cmd := exec.Command(name, args...)
	Hide(cmd)
	return cmd
}

// CommandContext is exec.CommandContext, without a console window on Windows.
func CommandContext(ctx context.Context, name string, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, name, args...)
	Hide(cmd)
	return cmd
}
