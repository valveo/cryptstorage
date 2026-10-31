package deps

import (
	"archive/zip"
	"cryptclient/nowindow"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
)

// rclone runs the synchronised folder (docs/design-features.md section 5.1). It is needed only when
// syncing is turned on, so it is fetched on first use rather than by install-deps. Same rules as the
// other components: an exact version from the official GitHub release, checked against its SHA-256
// (the values match rclone's own SHA256SUMS for the release).
const RcloneVersion = "1.71.1"

// rcloneMin is the oldest version with the bisync options the client uses (--compare,
// --conflict-resolve, --recover, --max-lock). Distribution packages are often older.
var rcloneMin = [2]int{1, 66}

var rcloneBase = "https://github.com/rclone/rclone/releases/download/v" + RcloneVersion + "/"

var rcloneZips = map[string]string{
	"linux/amd64":   "417e3da236f3a12d292da4e7287d67b1df558b8c2b280d092e563958ed724be7",
	"linux/arm64":   "cd0eb0d6faf1fdb697f191a316bbc6552770fafa097baf326ce61c04ab89f783",
	"windows/amd64": "a36b5e4ce336beac1349644f43374628add9fe1ae5ab7a3ed3cec5b8550ce041",
}

// ErrNoRclone means no usable rclone was found; InstallRclone can fetch one.
var ErrNoRclone = fmt.Errorf("rclone %d.%d or newer is needed for the synchronised folder", rcloneMin[0], rcloneMin[1])

func rcloneExe() string {
	if runtime.GOOS == "windows" {
		return "rclone.exe"
	}
	return "rclone"
}

// rcloneZip is the release file for this system.
func rcloneZip() (File, string, error) {
	plat := runtime.GOOS + "/" + runtime.GOARCH
	sum, ok := rcloneZips[plat]
	if !ok {
		return File{}, "", fmt.Errorf("no pinned rclone for %s; install rclone %d.%d or newer yourself", plat, rcloneMin[0], rcloneMin[1])
	}
	dir := fmt.Sprintf("rclone-v%s-%s-%s", RcloneVersion, runtime.GOOS, runtime.GOARCH)
	return File{Name: dir + ".zip", SHA256: sum}, dir + "/" + rcloneExe(), nil
}

// RclonePath returns a usable rclone: the installed or the user's own copy, else one on PATH that is
// new enough.
func RclonePath() (string, error) {
	for _, d := range programDirs() {
		own := filepath.Join(d, rcloneExe())
		if _, err := os.Stat(own); err == nil {
			return own, nil
		}
	}
	if p, err := exec.LookPath("rclone"); err == nil && rcloneNewEnough(p) {
		return p, nil
	}
	return "", ErrNoRclone
}

// RcloneInDir reports whether dir holds the client's rclone.
func RcloneInDir(dir string) bool { return exists(dir, rcloneExe()) }

var rcloneVersionRe = regexp.MustCompile(`rclone v(\d+)\.(\d+)`)

func rcloneNewEnough(path string) bool {
	out, err := nowindow.Command(path, "version").Output()
	if err != nil {
		return false
	}
	return versionAtLeast(string(out), rcloneMin)
}

func versionAtLeast(versionOutput string, min [2]int) bool {
	m := rcloneVersionRe.FindStringSubmatch(versionOutput)
	if m == nil {
		return false
	}
	major, _ := strconv.Atoi(m[1])
	minor, _ := strconv.Atoi(m[2])
	return major > min[0] || (major == min[0] && minor >= min[1])
}

// InstallRclone downloads the pinned rclone, checks it, and puts the program into the shared folder
// for an administrator (the installer), else into BinDir.
func InstallRclone(say Progress) (string, error) {
	dir := installDir()
	f, member, err := rcloneZip()
	if err != nil {
		return "", err
	}
	tmp, err := os.MkdirTemp("", "cryptstorage-rclone-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(tmp)
	say("Downloading rclone %s (the synchronisation program, about 25 MB)...", RcloneVersion)
	zipPath, err := Fetch(nil, rcloneBase, f, tmp)
	if err != nil {
		return "", fmt.Errorf("rclone: %w", err)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	dst := filepath.Join(dir, rcloneExe())
	if err := extractMember(zipPath, member, dst); err != nil {
		return "", fmt.Errorf("rclone: %w", err)
	}
	return dst, nil
}

// extractMember copies one named file out of a (checksum-verified) zip, via a temporary name so a
// half-written program is never left at dst.
func extractMember(zipPath, member, dst string) error {
	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		return err
	}
	defer zr.Close()
	for _, zf := range zr.File {
		if zf.Name != member {
			continue
		}
		in, err := zf.Open()
		if err != nil {
			return err
		}
		defer in.Close()
		tmp := dst + ".part"
		out, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
		if err != nil {
			return err
		}
		if _, err := io.Copy(out, in); err != nil {
			out.Close()
			os.Remove(tmp)
			return err
		}
		if err := out.Close(); err != nil {
			os.Remove(tmp)
			return err
		}
		return os.Rename(tmp, dst)
	}
	return errors.New(member + " is missing from the download")
}
