package diskenc

// bitlocker reads Explorer's System.Volume.BitLockerProtection value for a drive. It is in a file of its
// own so the mapping is tested on every platform.
func bitlocker(drive, value string) Result {
	switch value {
	case "1", "3", "6":
		return Result{Encrypted, "BitLocker on " + drive}
	case "2":
		return Result{NotEncrypted, "BitLocker off on " + drive}
	case "4":
		return Result{NotEncrypted, "BitLocker is being turned off on " + drive}
	case "5":
		return Result{NotEncrypted, "BitLocker suspended on " + drive}
	case "8":
		// Device encryption that was never activated: the data is encrypted, but the key is stored in the clear
		return Result{NotEncrypted, "BitLocker waiting for activation on " + drive}
	}
	return Result{Unknown, "BitLocker state of " + drive + " unknown"}
}
