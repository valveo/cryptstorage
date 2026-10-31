package stickkey

import (
	"crypto/rand"
	"errors"
	"testing"

	"cryptclient/apiclient"
	"cryptclient/crypto"
)

const testStick = "0f8fad5b-d9cb-469f-a165-70867728950e"

// fakeAPI is the server's side: secrets by stick id.
type fakeAPI map[string][]byte

func (f fakeAPI) CreateStick(string) (string, []byte, error) {
	s := make([]byte, 32)
	rand.Read(s)
	f[testStick] = s
	return testStick, append([]byte(nil), s...), nil
}

func (f fakeAPI) StickSecret(id string) ([]byte, error) {
	s, ok := f[id]
	if !ok {
		return nil, apiclient.ErrStickRevoked
	}
	return append([]byte(nil), s...), nil
}

func TestSealOpenReseal(t *testing.T) {
	api := fakeAPI{}
	pem := []byte("private key")
	old, _ := crypto.EncryptKey(pem, "old password here")
	if got, err := Open(api, old, "old password here"); err != nil || string(got) != "private key" {
		t.Fatalf("open an unsealed key: %v", err)
	}

	blob, err := Seal(api, pem, "old password here", "laptop")
	if err != nil || !Sealed(blob) {
		t.Fatalf("seal: %v", err)
	}
	if got, err := Open(api, blob, "old password here"); err != nil || string(got) != "private key" {
		t.Fatalf("open the sealed key: %v", err)
	}
	if _, err := Open(api, blob, "a wrong password!"); err == nil {
		t.Fatal("a wrong password opened the sealed key")
	}

	re, err := Reseal(api, blob, pem, "new password here")
	if err != nil {
		t.Fatal(err)
	}
	if got, err := Open(api, re, "new password here"); err != nil || string(got) != "private key" {
		t.Fatalf("open after reseal: %v", err)
	}

	// a revoked stick does not open, whatever the password
	delete(api, testStick)
	if _, err := Open(api, re, "new password here"); !errors.Is(err, apiclient.ErrStickRevoked) {
		t.Fatalf("revoked stick: %v", err)
	}
}

func TestIDRoundTrip(t *testing.T) {
	id, err := parseID(testStick)
	if err != nil || formatID(id) != testStick {
		t.Fatalf("%v %s", err, formatID(id))
	}
	if _, err := parseID("not-an-id"); err == nil {
		t.Fatal("accepted a bad id")
	}
}

func TestIDOfASealedKey(t *testing.T) {
	blob, err := Seal(fakeAPI{}, []byte("private key"), "a password here", "laptop")
	if err != nil {
		t.Fatal(err)
	}
	if id, ok := ID(blob); !ok || id != testStick {
		t.Fatalf("%q %v", id, ok)
	}
	plain, _ := crypto.EncryptKey([]byte("private key"), "a password here")
	if _, ok := ID(plain); ok {
		t.Fatal("an unsealed key has no stick id")
	}
}
