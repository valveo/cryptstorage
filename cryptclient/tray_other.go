//go:build !windows && !linux

package main

func hasConsole() bool { return true }

func cmdTrayWindows() {}

func startTrayAfterSetup() {}

// cmdTrayDesktop: no tray icon on this system (macOS uses the terminal).
func cmdTrayDesktop() bool { return false }

func trayRunning() bool { return false }
