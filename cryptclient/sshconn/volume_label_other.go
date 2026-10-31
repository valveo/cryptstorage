//go:build !windows

package sshconn

func volumeLabel(root string) (string, bool) { return "", false }
