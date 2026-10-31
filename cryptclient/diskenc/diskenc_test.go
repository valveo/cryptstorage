package diskenc

import (
	"strings"
	"testing"
)

func TestBitLockerValues(t *testing.T) {
	for v, want := range map[string]State{"1": Encrypted, "3": Encrypted, "6": Encrypted, "2": NotEncrypted,
		"5": NotEncrypted, "8": NotEncrypted, "": Unknown, "0": Unknown} {
		if got := bitlocker("C:", v); got.State != want {
			t.Errorf("%q: got %v, want %v", v, got.State, want)
		}
	}
}

func TestWarningOnlyWhenNotEncrypted(t *testing.T) {
	if Warning("/x", Result{Encrypted, "LUKS"}) != "" || Warning("/x", Result{Unknown, "?"}) != "" {
		t.Fatal("warned without a reason")
	}
	if w := Warning("/x", Result{NotEncrypted, "BitLocker off on C:"}); !strings.Contains(w, "BitLocker off on C:") {
		t.Fatalf("warning: %s", w)
	}
}
