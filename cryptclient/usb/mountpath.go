package usb

import (
	"bufio"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
)

// MountPath returns where the file system of the stick at devicePath is mounted on Linux and
// macOS, or "" when none of its partitions is mounted. The TLS pin and the server's SSH host key
// are kept there. There is deliberately no fallback to a temporary directory: on a shared
// /tmp another local user could plant a pin, and elsewhere the pins would silently not persist.
// Windows uses WindowsMountRoot instead.
func MountPath(devicePath string) string {
	switch runtime.GOOS {
	case "linux":
		f, err := os.Open("/proc/mounts")
		if err != nil {
			return ""
		}
		defer f.Close()
		dev := devicePath
		if resolved, err := filepath.EvalSymlinks(devicePath); err == nil {
			dev = resolved
		}
		return linuxMountPath(f, dev)
	case "darwin":
		out, err := exec.Command("mount").Output()
		if err != nil {
			return ""
		}
		return darwinMountPath(string(out), devicePath)
	}
	return ""
}

// File systems a stick's data partition normally has; preferred over anything else mounted from it.
var stickFS = map[string]bool{"vfat": true, "exfat": true, "msdos": true, "ntfs": true, "ntfs3": true, "fuseblk": true}

// linuxMountPath reads /proc/mounts ("device mountpoint fstype options 0 0"; spaces in paths are \040).
func linuxMountPath(mounts io.Reader, devicePath string) string {
	partition := regexp.MustCompile("^" + regexp.QuoteMeta(devicePath) + `p?[0-9]+$`)
	fallback := ""
	sc := bufio.NewScanner(mounts)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 3 || !partition.MatchString(f[0]) {
			continue
		}
		dir := unescapeMount(f[1])
		if stickFS[f[2]] {
			return dir
		}
		if fallback == "" {
			fallback = dir
		}
	}
	return fallback
}

// darwinMountPath reads the output of mount(8): "/dev/disk4s1 on /Volumes/MY STICK (msdos, local, ...)".
func darwinMountPath(mountOutput, devicePath string) string {
	disk := strings.Replace(devicePath, "/dev/rdisk", "/dev/disk", 1)
	partition := regexp.MustCompile("^" + regexp.QuoteMeta(disk) + `s[0-9]+$`)
	fallback := ""
	for _, line := range strings.Split(mountOutput, "\n") {
		dev, rest, ok := strings.Cut(line, " on ")
		if !ok || !partition.MatchString(dev) {
			continue
		}
		i := strings.LastIndex(rest, " (")
		if i < 0 {
			continue
		}
		dir, opts := rest[:i], rest[i+2:]
		fs, _, _ := strings.Cut(opts, ",")
		if stickFS[strings.TrimSuffix(fs, ")")] {
			return dir
		}
		if fallback == "" {
			fallback = dir
		}
	}
	return fallback
}

var octalEscape = regexp.MustCompile(`\\[0-7]{3}`)

func unescapeMount(s string) string {
	return octalEscape.ReplaceAllStringFunc(s, func(m string) string {
		n, _ := strconv.ParseUint(m[1:], 8, 8)
		return string(rune(n))
	})
}
