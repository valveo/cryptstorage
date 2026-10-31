//go:build !windows

package nowindow

import "os/exec"

// Hide does nothing outside Windows: there programs do not get windows of their own.
func Hide(*exec.Cmd) {}

// EndWithMe does nothing outside Windows, where the helpers end with the client's mount anyway.
func EndWithMe(int) {}
