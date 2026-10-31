package volume

import (
	"errors"
	"strings"
	"testing"

	"cryptclient/apiclient"
)

// Under policy "escrow" a "no" stops before anything reaches the server: the API is nil here,
// so any call to it would panic.
func TestInitWithoutEscrowConsentCreatesNothing(t *testing.T) {
	key := strings.Repeat("cd", 32)
	info := &apiclient.ServerInfo{StorageMode: "e2ee", RecoveryPolicy: "escrow", EscrowPublicKey: &key}
	c := &Conn{CipherDir: t.TempDir()}
	for name, consent := range map[string]func(string) bool{
		"not asked": nil,
		"declined":  func(string) bool { return false },
	} {
		if _, err := Init(c, InitParams{Info: info, ConsentEscrow: consent}); !errors.Is(err, ErrEscrowDeclined) {
			t.Fatalf("%s: got %v, want ErrEscrowDeclined", name, err)
		}
	}
}
