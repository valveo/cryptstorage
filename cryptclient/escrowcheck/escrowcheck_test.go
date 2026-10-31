package escrowcheck

import (
	"strings"
	"testing"

	"cryptclient/apiclient"
)

func info(policy, key string) *apiclient.ServerInfo {
	i := &apiclient.ServerInfo{StorageMode: "e2ee", RecoveryPolicy: policy}
	if key != "" {
		i.EscrowPublicKey = &key
	}
	return i
}

func TestFingerprintMatchesTheServer(t *testing.T) {
	// hashlib.sha256(bytes.fromhex("cd" * 32)).hexdigest()
	fp, err := Fingerprint(strings.Repeat("cd", 32))
	if err != nil || fp != "7969ec0fcb8b648dfde24b1d0ae24568d398dcc3a83b80a850f973238cdfd3d9" {
		t.Fatalf("fingerprint %q %v", fp, err)
	}
	if _, err := Fingerprint("abcd"); err == nil {
		t.Fatal("a short key must be refused")
	}
	if got := Short(strings.Repeat("ab12", 16)); got != "ab12 ab12 ab12 ab12 ab12 ab12 ab12 ab12" {
		t.Fatalf("Short = %q", got)
	}
}

func TestRecordRoundTripAndChanges(t *testing.T) {
	dir := t.TempDir()
	if _, found, err := Load(dir); found || err != nil {
		t.Fatalf("empty stick: %v %v", found, err)
	}
	off, _ := FromServer(info("user", ""))
	on, _ := FromServer(info("both", strings.Repeat("cd", 32)))
	other, _ := FromServer(info("both", strings.Repeat("ef", 32)))
	if err := Save(dir, off); err != nil {
		t.Fatal(err)
	}
	got, found, err := Load(dir)
	if err != nil || !found || got != off {
		t.Fatalf("load: %+v %v %v", got, found, err)
	}
	for _, c := range []struct {
		from, to Record
		want     string
	}{
		{off, off, ""},
		{off, on, "turned escrow ON"},
		{on, off, "escrow only really ends with a new storage key"},
		{on, other, "escrow key changed"},
	} {
		msg := Change(c.from, c.to)
		if (c.want == "" && msg != "") || !strings.Contains(msg, c.want) {
			t.Fatalf("Change(%+v, %+v) = %q, want %q", c.from, c.to, msg, c.want)
		}
	}
	if _, err := FromServer(info("escrow", "")); err == nil {
		t.Fatal("escrow on without a key must be an error")
	}
}
