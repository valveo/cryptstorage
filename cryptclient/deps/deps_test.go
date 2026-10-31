package deps

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFetchVerifiesChecksum(t *testing.T) {
	body := []byte("pretend installer")
	sum := sha256.Sum256(body)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(body) }))
	defer srv.Close()
	dir := t.TempDir()

	p, err := Fetch(srv.Client(), srv.URL+"/", File{"a.msi", hex.EncodeToString(sum[:])}, dir)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(p); string(got) != string(body) {
		t.Fatal("wrong content")
	}

	_, err = Fetch(srv.Client(), srv.URL+"/", File{"b.msi", strings.Repeat("0", 64)}, dir)
	if !errors.Is(err, ErrHashMismatch) {
		t.Fatalf("a wrong checksum must be refused, got %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "b.msi")); err == nil {
		t.Fatal("a file with a wrong checksum must be deleted")
	}
}

func TestFetchRefusesPlainHTTPAndErrors(t *testing.T) {
	if _, err := Fetch(nil, "http://example.com/", File{"a", "00"}, t.TempDir()); err == nil {
		t.Fatal("plain HTTP must be refused")
	}
	srv := httptest.NewTLSServer(http.NotFoundHandler())
	defer srv.Close()
	if _, err := Fetch(srv.Client(), srv.URL+"/", File{"a", "00"}, t.TempDir()); err == nil {
		t.Fatal("a 404 must be an error")
	}
}

func TestPinsAreWellFormed(t *testing.T) {
	for _, c := range All() {
		if !strings.HasPrefix(c.BaseURL, "https://github.com/") || !strings.HasSuffix(c.BaseURL, "/") {
			t.Errorf("%s: bad base URL %q", c.Name, c.BaseURL)
		}
		for _, f := range c.Files {
			if len(f.SHA256) != 64 {
				t.Errorf("%s/%s: checksum is not 64 hex characters", c.Name, f.Name)
			}
			if _, err := hex.DecodeString(f.SHA256); err != nil {
				t.Errorf("%s/%s: %v", c.Name, f.Name, err)
			}
		}
	}
}

func TestNeedsAdmin(t *testing.T) {
	if NeedsAdmin([]Component{{Kind: Exe}}) {
		t.Fatal("copying an exe needs no administrator rights")
	}
	if !NeedsAdmin([]Component{{Kind: Exe}, {Kind: MSI}}) {
		t.Fatal("an MSI does")
	}
}

func TestSharedDirFor(t *testing.T) {
	pf := filepath.Join(t.TempDir(), "Program Files")
	app := filepath.Join(pf, "CryptStorage")
	cases := []struct {
		exe  string
		want string
	}{
		{filepath.Join(app, "cryptclient.exe"), app},
		// the root itself is no app folder
		{filepath.Join(pf, "cryptclient.exe"), ""},
		// a sibling with the same prefix
		{filepath.Join(pf+" (x86)", "CryptStorage", "cryptclient.exe"), ""},
		// a loose copy elsewhere
		{filepath.Join(t.TempDir(), "claude", "cryptclient.exe"), ""},
		// not under the root after cleaning
		{filepath.Join(pf, "..", "elsewhere", "cryptclient.exe"), ""},
	}
	for _, c := range cases {
		if got := sharedDirFor(c.exe, "", pf); got != c.want {
			t.Errorf("sharedDirFor(%q) = %q, want %q", c.exe, got, c.want)
		}
	}
}

func TestComponentInDir(t *testing.T) {
	dir := t.TempDir()
	c := Component{Kind: Exe, Files: []File{{Name: "a.exe"}, {Name: "b.exe"}}}
	os.WriteFile(filepath.Join(dir, "a.exe"), nil, 0o644)
	if c.InDir(dir) {
		t.Fatal("one file is missing")
	}
	os.WriteFile(filepath.Join(dir, "b.exe"), nil, 0o644)
	if !c.InDir(dir) {
		t.Fatal("both files are there")
	}
}

func TestRclonePinsAreWellFormed(t *testing.T) {
	if !strings.HasPrefix(rcloneBase, "https://github.com/rclone/rclone/releases/download/") {
		t.Errorf("bad rclone base URL %q", rcloneBase)
	}
	for plat, sum := range rcloneZips {
		if _, err := hex.DecodeString(sum); err != nil || len(sum) != 64 {
			t.Errorf("%s: bad checksum %q", plat, sum)
		}
	}
}

func TestRcloneVersionCheck(t *testing.T) {
	cases := map[string]bool{
		"rclone v1.71.1\n- os/version: ubuntu": true,
		"rclone v1.66.0":                       true,
		"rclone v1.60.1-DEV":                   false,
		"rclone v2.0.0":                        true,
		"something else":                       false,
	}
	for out, want := range cases {
		if got := versionAtLeast(out, rcloneMin); got != want {
			t.Errorf("%q: got %v, want %v", out, got, want)
		}
	}
}

func TestExtractMember(t *testing.T) {
	dir := t.TempDir()
	zpath := filepath.Join(dir, "r.zip")
	zf, _ := os.Create(zpath)
	zw := zip.NewWriter(zf)
	w, _ := zw.Create("rclone-vX-linux-amd64/README.txt")
	w.Write([]byte("readme"))
	w, _ = zw.Create("rclone-vX-linux-amd64/rclone")
	w.Write([]byte("program"))
	zw.Close()
	zf.Close()
	dst := filepath.Join(dir, "rclone")
	if err := extractMember(zpath, "rclone-vX-linux-amd64/rclone", dst); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(dst); string(b) != "program" {
		t.Fatalf("got %q", b)
	}
	if err := extractMember(zpath, "missing/rclone", dst+"2"); err == nil {
		t.Fatal("a missing member must be an error")
	}
}

func TestMSILogExcerpt(t *testing.T) {
	text := "MSI (s) (A0:B4) Note: 1: 1708\r\nAction start 10:00:00: InstallFiles.\r\nCustomAction InstallDriver returned actual error code 1603\r\nMSI (s) (A0:B4) Product: Dokan -- Installation failed because a Windows reboot is still pending.\r\nAction ended 10:00:01: InstallFinalize. Return value 3.\r\nMSI (s) (A0:B4) Note: 1: 2228 2:  3: Error\r\n"
	var utf16 []byte
	utf16 = append(utf16, 0xFF, 0xFE)
	for _, r := range text {
		utf16 = append(utf16, byte(r), byte(r>>8))
	}
	for name, b := range map[string][]byte{"ansi": []byte(text), "utf16": utf16} {
		path := filepath.Join(t.TempDir(), "msi.log")
		if err := os.WriteFile(path, b, 0o600); err != nil {
			t.Fatal(err)
		}
		got := msiLogExcerpt(path)
		if !strings.Contains(got, "InstallDriver returned actual error code 1603") || !strings.Contains(got, "reboot is still pending") || strings.Contains(got, "Note: 1:") {
			t.Errorf("%s: excerpt misses the failure:\n%s", name, got)
		}
	}
	if msiLogExcerpt(filepath.Join(t.TempDir(), "none.log")) != "" {
		t.Error("a missing log should give no excerpt")
	}
}
