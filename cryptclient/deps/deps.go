// Package deps installs the Windows components the client needs: the Dokan driver and cppcryptfs
// (open the encrypted volume), and WinFsp with SSHFS-Win (connect to the server).
//
// Every component is pinned to an exact version and a SHA-256 taken from the official GitHub release
// (see .github/workflows/deps-hashes.yml). A file whose hash differs is never run. The pin is
// the trust anchor: bumping a version is a reviewed change, not a "latest" download.
package deps

import (
	"cryptclient/appdir"
	"cryptclient/nowindow"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

type Kind int

const (
	MSI Kind = iota // installed silently with msiexec, needs administrator rights
	Exe             // copied into the user's own folder, no administrator rights
)

// File is one downloadable file of a component.
type File struct {
	Name   string
	SHA256 string
}

// Component is one thing that has to be present.
type Component struct {
	Name    string
	Why     string // one sentence for the user
	Kind    Kind
	BaseURL string // release download directory
	Files   []File
	Present func() bool
}

func env(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

// BinDir is where the unprivileged programs (cppcryptfs, rclone) are kept: %LOCALAPPDATA%\cryptstorage
// on Windows, ~/.local/share/cryptstorage/bin elsewhere.
func BinDir() string {
	if runtime.GOOS != "windows" {
		base := os.Getenv("XDG_DATA_HOME")
		if base == "" {
			home, _ := os.UserHomeDir()
			base = filepath.Join(home, ".local", "share")
		}
		return filepath.Join(appdir.In(base), "bin")
	}
	base := os.Getenv("LOCALAPPDATA")
	if base == "" {
		base, _ = os.UserHomeDir()
	}
	return appdir.In(base)
}

// SharedDir is the installed program's own folder (Program Files\CryptStorage) when the client runs from
// under Program Files, else "". The installer puts cppcryptfs and rclone there too: antivirus
// heuristics such as F-Secure DeepGuard quarantine unsigned programs that run from the user profile.
// Only an administrator can write there, so the user's own copies stay in BinDir.
func SharedDir() string {
	if runtime.GOOS != "windows" {
		return ""
	}
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	return sharedDirFor(exe, os.Getenv("ProgramFiles"), os.Getenv("ProgramW6432"))
}

// sharedDirFor returns exe's folder when it lies under one of the Program Files roots.
func sharedDirFor(exe string, roots ...string) string {
	dir := filepath.Dir(exe)
	for _, root := range roots {
		if root == "" {
			continue
		}
		rel, err := filepath.Rel(root, dir)
		if err == nil && rel != "." && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return dir
		}
	}
	return ""
}

// programDirs are the folders searched for the helper programs, the installed one first.
func programDirs() []string {
	if d := SharedDir(); d != "" {
		return []string{d, BinDir()}
	}
	return []string{BinDir()}
}

// installDir is where Install puts the helper programs: the shared folder for an administrator
// (the installer), else the user's own folder.
func installDir() string {
	if d := SharedDir(); d != "" && IsAdmin() {
		return d
	}
	return BinDir()
}

// hasProgram reports whether all the named programs are in one of programDirs.
func hasProgram(names ...string) bool {
	for _, d := range programDirs() {
		if allIn(d, names...) {
			return true
		}
	}
	return false
}

func allIn(dir string, names ...string) bool {
	for _, n := range names {
		if !exists(dir, n) {
			return false
		}
	}
	return true
}

// InDir reports whether all of an Exe component's files are in dir.
func (c Component) InDir(dir string) bool {
	names := make([]string, len(c.Files))
	for i, f := range c.Files {
		names[i] = f.Name
	}
	return allIn(dir, names...)
}

func exists(parts ...string) bool {
	_, err := os.Stat(filepath.Join(parts...))
	return err == nil
}

// All returns the pinned components in install order.
func All() []Component {
	pf := env("ProgramFiles", `C:\Program Files`)
	pf86 := env("ProgramFiles(x86)", `C:\Program Files (x86)`)
	sys := env("SystemRoot", `C:\Windows`)
	return []Component{
		{
			Name: "Dokan 2.3.1", Why: "lets Windows show the decrypted files as a drive", Kind: MSI,
			BaseURL: "https://github.com/dokan-dev/dokany/releases/download/v2.3.1.1000/",
			Files:   []File{{"Dokan_x64.msi", "69ff8cb37bfec3a75921c85ffd1c6370b50a9ec4ecef2cf3a009d488dcbf5465"}},
			Present: func() bool { return exists(sys, "System32", "dokan2.dll") },
		},
		{
			Name: "WinFsp 2.1", Why: "lets Windows connect to the server's storage", Kind: MSI,
			BaseURL: "https://github.com/winfsp/winfsp/releases/download/v2.1/",
			Files:   []File{{"winfsp-2.1.25156.msi", "073a70e00f77423e34bed98b86e600def93393ba5822204fac57a29324db9f7a"}},
			Present: func() bool { return exists(pf86, "WinFsp", "bin") || exists(pf, "WinFsp", "bin") },
		},
		{
			Name: "SSHFS-Win 3.5", Why: "the secure connection to the server's storage", Kind: MSI,
			BaseURL: "https://github.com/winfsp/sshfs-win/releases/download/v3.5.20357/",
			Files:   []File{{"sshfs-win-3.5.20357-x64.msi", "1657e397f8dce1c2d2e3220007f9c9f882631882b9bec4608f7835e87dcd096c"}},
			Present: func() bool { return exists(pf, "SSHFS-Win", "bin") },
		},
		{
			Name: "cppcryptfs 1.4.5", Why: "decrypts your files on this computer", Kind: Exe,
			BaseURL: "https://github.com/bailey27/cppcryptfs/releases/download/v1.4.5.0/",
			Files: []File{
				{"cppcryptfs.exe", "cdaf1b02e7a1ea42e5e0349f8c65d15c0852958b8c795978a8e60857f3af6d08"},
				{"cppcryptfsctl.exe", "59ca4759461c38431c693713c014bf4419b70a03247e732f89858dcc1132e2a3"},
			},
			Present: func() bool { return hasProgram("cppcryptfs.exe", "cppcryptfsctl.exe") },
		},
	}
}

// Missing returns the components that are not installed. Off Windows nothing is needed.
func Missing() []Component {
	if runtime.GOOS != "windows" {
		return nil
	}
	var out []Component
	for _, c := range All() {
		if !c.Present() {
			out = append(out, c)
		}
	}
	return out
}

// NeedsAdmin reports whether installing any of cs needs administrator rights.
func NeedsAdmin(cs []Component) bool {
	for _, c := range cs {
		if c.Kind == MSI {
			return true
		}
	}
	return false
}

// ErrHashMismatch means the downloaded file is not the pinned one.
var ErrHashMismatch = errors.New("the downloaded file does not match the expected checksum; it was not installed")

// Fetch downloads one file into dir and verifies its checksum before returning its path.
// client may be nil (a client with a timeout is used).
func Fetch(client *http.Client, base string, f File, dir string) (string, error) {
	if !strings.HasPrefix(base, "https://") {
		return "", errors.New("refusing a non-HTTPS download")
	}
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Minute}
	}
	resp, err := client.Get(base + f.Name)
	if err != nil {
		return "", fmt.Errorf("could not download %s: %w", f.Name, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("could not download %s: server answered %s", f.Name, resp.Status)
	}
	path := filepath.Join(dir, f.Name)
	out, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	_, err = io.Copy(io.MultiWriter(out, h), resp.Body)
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(path)
		return "", fmt.Errorf("download of %s was interrupted: %w", f.Name, err)
	}
	if hex.EncodeToString(h.Sum(nil)) != strings.ToLower(f.SHA256) {
		os.Remove(path)
		return "", ErrHashMismatch
	}
	return path, nil
}

// Progress receives short sentences for the user.
type Progress func(format string, args ...any)

// Install downloads, verifies and installs the components. MSI components need an elevated process.
func Install(cs []Component, say Progress) error {
	tmp, err := os.MkdirTemp("", "cryptstorage-deps-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	for _, c := range cs {
		say("Installing %s - %s...", c.Name, c.Why)
		var paths []string
		for _, f := range c.Files {
			p, err := Fetch(nil, c.BaseURL, f, tmp)
			if err != nil {
				return fmt.Errorf("%s: %w", c.Name, err)
			}
			paths = append(paths, p)
		}
		switch c.Kind {
		case MSI:
			if err := runMSI(paths[0]); err != nil {
				return fmt.Errorf("%s: %w", c.Name, err)
			}
		case Exe:
			dir := installDir()
			if err := os.MkdirAll(dir, 0o755); err != nil {
				return err
			}
			for i, f := range c.Files {
				if err := copyFile(paths[i], filepath.Join(dir, f.Name)); err != nil {
					return fmt.Errorf("%s: %w", c.Name, err)
				}
			}
		}
	}
	return nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// RebootRequired is returned (wrapped) when an installer asked for a restart; the install itself worked.
var RebootRequired = errors.New("Windows asks for a restart to finish installing a driver")

func runMSI(path string) error {
	logPath := filepath.Join(os.TempDir(), "cryptstorage-"+strings.TrimSuffix(filepath.Base(path), ".msi")+"-install.log")
	cmd := exec.Command("msiexec", "/i", path, "/qn", "/norestart", "/l*v", logPath)
	out, err := cmd.CombinedOutput()
	if err == nil {
		os.Remove(logPath)
		return nil
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		switch ee.ExitCode() {
		case 3010, 1641:
			os.Remove(logPath)
			return RebootRequired
		case 1603:
			hint := "administrator rights are probably missing"
			if IsAdmin() {
				hint = "it ran as administrator, so the reason is in the installer's log"
			}
			return fmt.Errorf("the installer failed (code 1603); %s.\nLog: %s%s", hint, logPath, msiLogExcerpt(logPath))
		}
	}
	return fmt.Errorf("msiexec: %v %s\nLog: %s%s", err, strings.TrimSpace(string(out)), logPath, msiLogExcerpt(logPath))
}

// msiLogExcerpt returns the lines of an msiexec log that usually name the failure: the ones before
// the first action that failed ("Return value 3"), without msiexec's internal notes. Empty when nothing is found.
func msiLogExcerpt(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	lines := strings.Split(strings.ReplaceAll(decodeLog(b), "\r\n", "\n"), "\n")
	var picked []string
	for i, l := range lines {
		if strings.Contains(l, "Return value 3") {
			from := i - 12
			if from < 0 {
				from = 0
			}
			for _, w := range lines[from : i+1] {
				if strings.TrimSpace(w) != "" && !strings.Contains(w, "Note: 1:") {
					picked = append(picked, w)
				}
			}
			break
		}
	}
	if len(picked) == 0 {
		return ""
	}
	return "\nFrom the log:\n  " + strings.Join(picked, "\n  ")
}

// decodeLog turns an msiexec log into text; it is UTF-16LE on most Windows versions.
func decodeLog(b []byte) string {
	if len(b) >= 2 && b[0] == 0xFF && b[1] == 0xFE {
		b = b[2:]
	} else if len(b) < 2 || b[1] != 0 {
		return string(b)
	}
	u := make([]rune, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		u = append(u, rune(uint16(b[i])|uint16(b[i+1])<<8))
	}
	return string(u)
}

// IsAdmin reports whether the process may install drivers.
func IsAdmin() bool {
	if runtime.GOOS != "windows" {
		return true
	}
	return nowindow.Command("net", "session").Run() == nil
}

// RunElevated starts this program again with the given arguments and administrator rights, and waits.
// Windows shows its own permission prompt.
func RunElevated(exe string, args ...string) error {
	quoted := make([]string, len(args))
	for i, a := range args {
		quoted[i] = "'" + strings.ReplaceAll(a, "'", "''") + "'"
	}
	script := fmt.Sprintf(
		"$p = Start-Process -FilePath '%s' -ArgumentList %s -Verb RunAs -Wait -PassThru; exit $p.ExitCode",
		strings.ReplaceAll(exe, "'", "''"), strings.Join(quoted, ","))
	out, err := nowindow.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", script).CombinedOutput()
	if err != nil {
		return fmt.Errorf("the permission was refused or the installation failed: %v %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}
