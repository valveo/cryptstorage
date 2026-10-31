//go:build !linux && !windows && !darwin

package diskenc

// Advice names the encryption to turn on.
func Advice() string { return "disk encryption" }

func check(string) Result { return Result{Unknown, "not checked on this system"} }
