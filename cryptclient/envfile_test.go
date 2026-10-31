package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadEnvFile(t *testing.T) {
	f := filepath.Join(t.TempDir(), "env")
	os.WriteFile(f, []byte(`# comment
CRYPTSTORAGE_SERVER="https://storage.example.com"
CRYPTSTORAGE_MOUNT = /mnt/x
CRYPTSTORAGE_CERT_PIN=from-file
PATH=/tmp/evil
`), 0o600)
	t.Setenv("CRYPTSTORAGE_SERVER", "")
	os.Unsetenv("CRYPTSTORAGE_SERVER")
	t.Setenv("CRYPTSTORAGE_MOUNT", "")
	os.Unsetenv("CRYPTSTORAGE_MOUNT")
	t.Setenv("CRYPTSTORAGE_CERT_PIN", "from-env")
	path := os.Getenv("PATH")

	loadEnvFile(f)

	if got := os.Getenv("CRYPTSTORAGE_SERVER"); got != "https://storage.example.com" {
		t.Errorf("server %q", got)
	}
	if got := os.Getenv("CRYPTSTORAGE_MOUNT"); got != "/mnt/x" {
		t.Errorf("mount %q", got)
	}
	if got := os.Getenv("CRYPTSTORAGE_CERT_PIN"); got != "from-env" {
		t.Errorf("the environment should win, got %q", got)
	}
	if os.Getenv("PATH") != path {
		t.Error("the file changed PATH")
	}
}

func TestIsYes(t *testing.T) {
	for _, a := range []string{"y", "Y", "yes", " YES \n"} {
		if !isYes(a) {
			t.Errorf("%q not accepted", a)
		}
	}
	for _, a := range []string{"", "n", "no", "yess", "kyllä"} {
		if isYes(a) {
			t.Errorf("%q accepted", a)
		}
	}
}

func TestSaveSetting(t *testing.T) {
	f := filepath.Join(t.TempDir(), "cryptstorage", "env")
	if _, err := saveSetting(f, "CRYPTSTORAGE_SERVER", "https://a.example"); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(f, []byte("# mine\nCRYPTSTORAGE_SERVER=https://a.example\nCRYPTCLIENT_SYNC_DIR=/x\n"), 0o600)
	if _, err := saveSetting(f, "CRYPTSTORAGE_SERVER", "http://192.168.1.152:8099"); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(f)
	want := "# mine\nCRYPTCLIENT_SYNC_DIR=/x\nCRYPTSTORAGE_SERVER=http://192.168.1.152:8099\n"
	if string(b) != want {
		t.Errorf("got %q, want %q", b, want)
	}
}

func TestNormalizeServer(t *testing.T) {
	for in, want := range map[string]string{
		" storage.example.com/ ":     "https://storage.example.com",
		"http://192.168.1.152:8099":  "http://192.168.1.152:8099",
		"https://s.example.com/api/": "https://s.example.com/api",
		"   ":                        "",
	} {
		if got := normalizeServer(in); got != want {
			t.Errorf("%q: got %q, want %q", in, got, want)
		}
	}
}

func TestAskServerSavesReachableAddress(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("APPDATA", dir)
	t.Setenv("CRYPTSTORAGE_SERVER", "")
	os.Unsetenv("CRYPTSTORAGE_SERVER")
	answers := []string{"wrong.example", "http://good.example:8099"}
	ask := func(string) string { a := answers[0]; answers = answers[1:]; return a }
	reachable := func() error {
		if os.Getenv("CRYPTSTORAGE_SERVER") != "http://good.example:8099" {
			return os.ErrNotExist
		}
		return nil
	}
	if err := askServer(ask, reachable); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(envFilePath())
	if err != nil || string(b) != "CRYPTSTORAGE_SERVER=http://good.example:8099\n" {
		t.Fatalf("saved %q, %v", b, err)
	}
	// set now: not asked again
	if err := askServer(func(string) string { t.Fatal("asked again"); return "" }, reachable); err != nil {
		t.Fatal(err)
	}
}

func TestAskServerFindsAPIUnderSlashAPI(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("APPDATA", dir)
	t.Setenv("CRYPTSTORAGE_SERVER", "")
	os.Unsetenv("CRYPTSTORAGE_SERVER")
	ask := func(string) string { return "demo.example" }
	reachable := func() error {
		if os.Getenv("CRYPTSTORAGE_SERVER") != "https://demo.example/api" {
			return os.ErrNotExist
		}
		return nil
	}
	if err := askServer(ask, reachable); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(envFilePath())
	if err != nil || string(b) != "CRYPTSTORAGE_SERVER=https://demo.example/api\n" {
		t.Fatalf("saved %q, %v", b, err)
	}
}

func TestChangeServerKeepsOldAddressOnFailure(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("APPDATA", dir)
	t.Setenv("CRYPTSTORAGE_SERVER", "https://old.example/api")
	answers := []string{"bad.example", ""}
	ask := func(string) string { a := answers[0]; answers = answers[1:]; return a }
	if err := changeServer(ask, func(string) {}, func() error { return os.ErrNotExist }, ""); err == nil {
		t.Fatal("no error")
	}
	if got := os.Getenv("CRYPTSTORAGE_SERVER"); got != "https://old.example/api" {
		t.Fatalf("server now %q", got)
	}
}

func TestChangeServerSavesAndForgetsUsername(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("APPDATA", dir)
	t.Setenv("CRYPTSTORAGE_SERVER", "https://old.example/api")
	if f := usernameFile(); f != "" {
		os.MkdirAll(filepath.Dir(f), 0o700)         //nolint
		os.WriteFile(f, []byte("olduser\n"), 0o600) //nolint
	}
	ask := func(string) string { return "https://new.example/api" }
	if err := changeServer(ask, func(string) {}, func() error { return nil }, ""); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(envFilePath())
	if string(b) != "CRYPTSTORAGE_SERVER=https://new.example/api\n" {
		t.Fatalf("saved %q", b)
	}
	if savedUsername() != "" {
		t.Fatal("old username kept")
	}
}

func TestReloadEnvFileFollowsTheFileButNotTheRealEnvironment(t *testing.T) {
	f := filepath.Join(t.TempDir(), "env")
	t.Setenv("CRYPTCLIENT_SYNC_DIR", "from-env")
	os.Unsetenv("CRYPTSTORAGE_SERVER")
	t.Cleanup(func() { os.Unsetenv("CRYPTSTORAGE_SERVER"); startEnv = nil })
	startEnv = nil
	os.WriteFile(f, []byte("CRYPTSTORAGE_SERVER=https://old.example\nCRYPTCLIENT_SYNC_DIR=from-file\n"), 0o600) //nolint
	loadEnvFile(f)
	os.WriteFile(f, []byte("CRYPTSTORAGE_SERVER=https://new.example\nCRYPTCLIENT_SYNC_DIR=from-file\n"), 0o600) //nolint
	reloadEnvFile(f)
	if got := os.Getenv("CRYPTSTORAGE_SERVER"); got != "https://new.example" {
		t.Fatalf("server %q", got)
	}
	if got := os.Getenv("CRYPTCLIENT_SYNC_DIR"); got != "from-env" {
		t.Fatalf("sync dir %q", got)
	}
}
