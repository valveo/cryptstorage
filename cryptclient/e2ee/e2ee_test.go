package e2ee

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Written by the real gocryptfs 2.4.0 (-init -scryptn=10, passphrase "pass1").
const realMasterKey = "1a8248689307a78a2ae52ca931420bc18597c3efddb770cf25f8c5ee7863c9f4"

func TestReadsRealGocryptfsConfig(t *testing.T) {
	conf, err := os.ReadFile("testdata/gocryptfs-2.4.0-n10.conf")
	if err != nil {
		t.Fatal(err)
	}
	key, err := ReadMasterKey(conf, []byte("pass1"))
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(key) != realMasterKey {
		t.Fatalf("got %x", key)
	}
	if _, err := ReadMasterKey(conf, []byte("pass2")); err != ErrWrongPassphrase {
		t.Fatalf("want ErrWrongPassphrase, got %v", err)
	}
}

func TestConfRoundTrip(t *testing.T) {
	mk, _ := NewMasterKey()
	conf, err := MakeConf(mk, []byte("secret"), 10)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ReadMasterKey(conf, []byte("secret"))
	if err != nil || !bytes.Equal(got, mk) {
		t.Fatalf("round trip failed: %v", err)
	}
}

func TestHostileConfigIsRefused(t *testing.T) {
	bad := `{"EncryptedKey":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","ScryptObject":{"Salt":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","N":1073741824,"R":8,"P":1,"KeyLen":32},"Version":2}`
	if _, err := ReadMasterKey([]byte(bad), []byte("x")); err == nil || strings.Contains(err.Error(), "authentication") {
		t.Fatalf("expected a parameter error, got %v", err)
	}
}

// The feature flags are not covered by the wrapped key's authentication, so a server could switch
// file-name encryption off. Anything but our own flags is refused, and the copy the mount uses holds
// only the fields we know.
func TestTamperedFeatureFlagsAreRefused(t *testing.T) {
	mk, _ := NewMasterKey()
	conf, err := MakeConf(mk, []byte("pw"), 10)
	if err != nil {
		t.Fatal(err)
	}
	for _, flags := range [][]string{
		{"HKDF", "GCMIV128", "PlaintextNames"},
		{"HKDF", "GCMIV128", "EMENames", "LongNames", "Raw64"},                    // no DirIV
		{"HKDF", "GCMIV128", "DirIV", "EMENames", "LongNames", "Raw64", "AESSIV"}, // another cipher
		{"HKDF", "GCMIV128", "DirIV", "EMENames", "LongNames", "LongNames"},
		nil,
	} {
		var doc map[string]any
		json.Unmarshal(conf, &doc)
		doc["FeatureFlags"] = flags
		bad, _ := json.Marshal(doc)
		if _, err := ReadMasterKey(bad, []byte("pw")); !errors.Is(err, ErrUnsafeConf) {
			t.Errorf("flags %v: want ErrUnsafeConf, got %v", flags, err)
		}
		dir := t.TempDir()
		os.WriteFile(filepath.Join(dir, "gocryptfs.conf"), bad, 0o600)
		if _, _, err := LocalConf(dir); !errors.Is(err, ErrUnsafeConf) {
			t.Errorf("flags %v: LocalConf: want ErrUnsafeConf, got %v", flags, err)
		}
	}

	// the same flags in another order are fine, and an unknown field does not reach the local copy
	var doc map[string]any
	json.Unmarshal(conf, &doc)
	doc["FeatureFlags"] = []string{"Raw64", "LongNames", "EMENames", "DirIV", "GCMIV128", "HKDF"}
	doc["LongNameMax"] = 62
	doc["FIDO2"] = map[string]any{"CredentialID": "AAAA"}
	odd, _ := json.Marshal(doc)
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "gocryptfs.conf"), odd, 0o600)
	p, tmp, err := LocalConf(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmp)
	local, _ := os.ReadFile(p)
	if bytes.Contains(local, []byte("LongNameMax")) || bytes.Contains(local, []byte("FIDO2")) {
		t.Errorf("unknown fields reached the local copy: %s", local)
	}
	if got, err := ReadMasterKey(local, []byte("pw")); err != nil || !bytes.Equal(got, mk) {
		t.Errorf("the local copy does not open: %v", err)
	}
}

func TestRecoveryCode(t *testing.T) {
	mk, _ := NewMasterKey()
	code, err := RecoveryCode(mk)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseRecoveryCode(strings.ToLower(strings.ReplaceAll(code, "-", " ")))
	if err != nil || !bytes.Equal(got, mk) {
		t.Fatalf("parse failed: %v", err)
	}
	typo := []byte(code)
	if typo[0] == 'A' {
		typo[0] = 'B'
	} else {
		typo[0] = 'A'
	}
	if _, err := ParseRecoveryCode(string(typo)); err == nil {
		t.Fatal("typo not detected")
	}
}

func TestDeriveSeparatesKeys(t *testing.T) {
	a, err := Derive("Alice", "correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := Derive(" alice ", "correct horse battery")
	if a.AuthKey != b.AuthKey || !bytes.Equal(a.VolumePassphrase, b.VolumePassphrase) {
		t.Fatal("user name normalisation differs")
	}
	if a.AuthKey == string(a.VolumePassphrase) {
		t.Fatal("login key and volume passphrase must differ")
	}
	c, _ := Derive("bob", "correct horse battery")
	if c.AuthKey == a.AuthKey {
		t.Fatal("salt does not depend on the user")
	}
	// Stable vector: any change breaks every existing volume, so it must be deliberate.
	if a.AuthKey != "267d874caa4f5ad25ba061432ded57a0b369e31f327032d509f2a88363a569c4" ||
		string(a.VolumePassphrase) != "fe627d1d255dbc3d700e9f9dbe484d4d0c9b0e3fa56bd2c4aeee236259b69b4e" {
		t.Fatalf("derivation changed: %s %s", a.AuthKey, a.VolumePassphrase)
	}
}

// The decisive check: the real gocryptfs accepts a config written by us, and rejects a wrong passphrase.
func TestRealGocryptfsAcceptsOurConfig(t *testing.T) {
	bin, err := exec.LookPath("gocryptfs")
	if err != nil {
		t.Skip("gocryptfs is not installed")
	}
	dir := t.TempDir()
	mk, _ := NewMasterKey()
	conf, err := MakeConf(mk, []byte("right"), 10)
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(dir, "gocryptfs.conf"), conf, 0o600)
	os.WriteFile(filepath.Join(dir, "gocryptfs.diriv"), bytes.Repeat([]byte{7}, 16), 0o600)
	pw := filepath.Join(dir, "..", "pw-"+filepath.Base(dir))
	os.WriteFile(pw, []byte("right"), 0o600)
	defer os.Remove(pw)
	if out, err := exec.Command(bin, "-fsck", "-q", "-extpass", "cat "+pw, dir).CombinedOutput(); err != nil {
		t.Fatalf("gocryptfs refused our config: %v\n%s", err, out)
	}
	os.WriteFile(pw, []byte("wrong"), 0o600)
	if err := exec.Command(bin, "-fsck", "-q", "-extpass", "cat "+pw, dir).Run(); err == nil {
		t.Fatal("gocryptfs accepted a wrong passphrase")
	}
}

// Version 2 salts with the server's kdf_salt. The same vector is checked by webui/assets/derive.test.mjs
// and was reproduced independently with argon2-cffi and cryptography in Python.
func TestDeriveV2Vector(t *testing.T) {
	serverSalt := make([]byte, 32)
	for i := range serverSalt {
		serverSalt[i] = byte(i)
	}
	k, err := DeriveV2(serverSalt, " Alice ", "correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if k.AuthKey != "b38ae6047a72ec83205ac71fd8d8d9bf839c49575263db45e2630787162ee5d5" ||
		string(k.VolumePassphrase) != "1da42a3baceb922c8c853404024f7c9bda7e5bd35fff70355b54f038062fe40c" {
		t.Fatalf("v2 vector changed: %s %s", k.AuthKey, k.VolumePassphrase)
	}
	if _, err := DeriveV2(serverSalt[:31], "alice", "x"); err == nil {
		t.Fatal("a short server salt must be refused")
	}
}

func TestDeriveSet(t *testing.T) {
	old, err := DeriveSet("", "alice", "correct horse battery")
	if err != nil || old.Version != 1 || old.Legacy != nil || old.LegacyAuthKey() != "" {
		t.Fatalf("older server: %+v %v", old, err)
	}
	if old.Current.AuthKey != "267d874caa4f5ad25ba061432ded57a0b369e31f327032d509f2a88363a569c4" {
		t.Fatal("older server must get the version 1 keys")
	}
	saltHex := "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	s, err := DeriveSet(saltHex, "alice", "correct horse battery")
	if err != nil || s.Version != 2 {
		t.Fatal(err)
	}
	if s.Current.AuthKey != "b38ae6047a72ec83205ac71fd8d8d9bf839c49575263db45e2630787162ee5d5" ||
		s.LegacyAuthKey() != old.Current.AuthKey {
		t.Fatal("wrong keys in the set")
	}
	if s.For(1) != s.Legacy || s.For(2) != s.Current || len(s.Passphrases()) != 2 {
		t.Fatal("For/Passphrases")
	}
	for _, bad := range []string{"zz", "0001", saltHex + "00"} {
		if _, err := DeriveSet(bad, "alice", "x"); err == nil {
			t.Fatalf("malformed salt %q accepted", bad)
		}
	}
}

// With the real gocryptfs: a normal mount stores encrypted names, and a config whose flags the server
// changed to PlaintextNames is refused before gocryptfs sees it.
func TestMountUsesCheckedConfig(t *testing.T) {
	if _, err := exec.LookPath("gocryptfs"); err != nil {
		t.Skip("gocryptfs is not installed")
	}
	if _, err := os.Stat("/dev/fuse"); err != nil {
		t.Skip("no FUSE here")
	}
	cipher, plain := t.TempDir(), t.TempDir()
	mk, _ := NewMasterKey()
	pass := []byte("0123456789abcdef0123456789abcdef")
	conf, err := MakeConf(mk, pass, 10)
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteVolumeFiles(cipher, conf, bytes.Repeat([]byte{7}, 16)); err != nil {
		t.Fatal(err)
	}
	if err := MountVolume(cipher, plain, pass); err != nil {
		t.Skipf("cannot mount here: %v", err)
	}
	werr := os.WriteFile(filepath.Join(plain, "secret-name.txt"), []byte("x"), 0o600)
	if err := UnmountVolume(plain); err != nil {
		t.Fatal(err)
	}
	if werr != nil {
		t.Fatal(werr)
	}
	if _, err := os.Stat(filepath.Join(cipher, "secret-name.txt")); err == nil {
		t.Fatal("the file name is stored in the clear")
	}

	var doc map[string]any
	json.Unmarshal(conf, &doc)
	doc["FeatureFlags"] = []string{"HKDF", "GCMIV128", "PlaintextNames"}
	bad, _ := json.Marshal(doc)
	os.WriteFile(filepath.Join(cipher, "gocryptfs.conf"), bad, 0o600)
	if err := MountVolume(cipher, plain, pass); !errors.Is(err, ErrUnsafeConf) {
		UnmountVolume(plain)
		t.Fatalf("a config with PlaintextNames: want ErrUnsafeConf, got %v", err)
	}
}
