package stickserver

import (
	"errors"
	"testing"
)

const hostKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"

func TestCheck(t *testing.T) {
	demo := &Record{URL: "https://demo.example/api", ServerID: "id-demo"}
	old := &Record{URL: "http://192.168.1.152:8099"} // a server without stick secrets
	cases := []struct {
		name     string
		r        *Record
		url, id  string
		ok, same bool
	}{
		{"no record yet", nil, "https://x", "id-x", true, false},
		{"same server", demo, "https://demo.example/api", "id-demo", true, false},
		{"same server, new address", demo, "https://storage.example/api", "id-demo", true, false},
		{"another server", demo, "http://192.168.1.152:8099", "id-old", false, false},
		{"another server without ids", demo, "http://192.168.1.152:8099", "", false, false},
		{"same address, set up again", demo, "https://DEMO.example/api/", "id-new", false, true},
		{"same address, stick secrets turned off", demo, "https://demo.example/api", "", true, false},
		{"old record, same address", old, "http://192.168.1.152:8099/", "", true, false},
		{"old record, server now has ids", old, "http://192.168.1.152:8099", "id-old", true, false},
		{"old record, another address", old, "https://demo.example/api", "id-demo", false, false},
	}
	for _, c := range cases {
		err := Check(c.r, c.url, c.id)
		var other *OtherServerError
		if (err == nil) != c.ok || (err != nil && (!errors.As(err, &other) || other.SameAddress != c.same)) {
			t.Errorf("%s: got %v", c.name, err)
		}
	}
}

func TestSaveLoadUpdated(t *testing.T) {
	dir := t.TempDir()
	if r, err := Load(dir); r != nil || err != nil {
		t.Fatalf("empty stick: %v %v", r, err)
	}
	if r, _ := Load(""); r != nil {
		t.Fatal("no mount must give no record")
	}
	next, changed := Updated(nil, "https://a/api", "id-a", []string{hostKey, "garbage"})
	if !changed || len(next.HostKeys) != 1 || next.HostKeys[0][:7] != "SHA256:" {
		t.Fatalf("first record: %+v %v", next, changed)
	}
	if err := Save(dir, next); err != nil {
		t.Fatal(err)
	}
	r, err := Load(dir)
	if err != nil || r == nil || r.ServerID != "id-a" || r.URL != "https://a/api" {
		t.Fatalf("load: %+v %v", r, err)
	}
	if _, changed := Updated(r, "https://a/api", "id-a", nil); changed {
		t.Fatal("nothing new must not need saving")
	}
	if n, changed := Updated(r, "https://b/api", "", nil); !changed || n.ServerID != "id-a" || len(n.HostKeys) != 1 {
		t.Fatalf("a new address keeps the id and host keys: %+v", n)
	}
}
