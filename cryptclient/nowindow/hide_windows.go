package nowindow

import (
	"os/exec"
	"syscall"

	"golang.org/x/sys/windows"
)

// Hide makes cmd start without a console window. Other process settings already made are kept.
func Hide(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.CreationFlags |= windows.CREATE_NO_WINDOW
}
