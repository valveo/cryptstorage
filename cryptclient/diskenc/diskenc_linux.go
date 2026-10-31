package diskenc

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

func check(path string) Result {
	return linuxProbe{mountinfo: "/proc/self/mountinfo", sys: "/sys", rdev: statRdev}.check(path)
}

// Advice names the encryption to turn on.
func Advice() string { return "disk encryption (LUKS, usually chosen when installing Linux)" }

func statRdev(path string) (string, bool) {
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFBLK {
		return "", false
	}
	return fmt.Sprintf("%d:%d", unix.Major(uint64(st.Rdev)), unix.Minor(uint64(st.Rdev))), true
}

// linuxProbe reads the mount table and sysfs; tests point it at fake copies.
type linuxProbe struct {
	mountinfo, sys string
	rdev           func(path string) (string, bool)
}

type mount struct{ point, dev, fstype, source string }

func (l linuxProbe) check(path string) Result {
	m, err := l.mountOf(path)
	if err != nil {
		return Result{Unknown, err.Error()}
	}
	switch m.fstype {
	case "ecryptfs":
		return Result{Encrypted, "eCryptfs"}
	case "tmpfs", "ramfs":
		return Result{Unknown, "in memory (" + m.fstype + ")"}
	}
	dev := m.dev
	if strings.HasPrefix(m.source, "/dev/") {
		// btrfs and some others report an anonymous device number; the source names the real one
		if d, ok := l.rdev(m.source); ok {
			dev = d
		}
	}
	if strings.HasPrefix(dev, "0:") {
		return Result{Unknown, m.fstype + " file system"}
	}
	if _, err := os.Stat(filepath.Join(l.sys, "dev/block", dev)); err != nil {
		return Result{Unknown, "no block device for " + m.source}
	}
	if l.crypt(dev, 0) {
		return Result{Encrypted, "LUKS (dm-crypt)"}
	}
	return Result{NotEncrypted, "no LUKS under " + m.source}
}

// mountOf returns the mount whose mount point is the longest prefix of path.
func (l linuxProbe) mountOf(path string) (mount, error) {
	f, err := os.Open(l.mountinfo)
	if err != nil {
		return mount{}, err
	}
	defer f.Close()
	var best mount
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		// 36 35 98:0 /mnt1 /mnt2 rw,noatime master:1 - ext3 /dev/root rw,errors=continue
		fields := strings.Fields(sc.Text())
		sep := -1
		for i, f := range fields {
			if f == "-" {
				sep = i
				break
			}
		}
		if sep < 5 || len(fields) < sep+3 {
			continue
		}
		point := unescape(fields[4])
		if !under(path, point) || len(point) < len(best.point) {
			continue
		}
		best = mount{point: point, dev: fields[2], fstype: fields[sep+1], source: unescape(fields[sep+2])}
	}
	if best.point == "" {
		return mount{}, fmt.Errorf("no mount found for %s", path)
	}
	return best, sc.Err()
}

func under(path, point string) bool {
	return point == "/" || path == point || strings.HasPrefix(path, point+"/")
}

// unescape undoes the octal escapes of mountinfo (\040 for a space).
func unescape(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+4 <= len(s) {
			var c int
			if _, err := fmt.Sscanf(s[i+1:i+4], "%03o", &c); err == nil {
				b.WriteByte(byte(c))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// crypt reports whether the device, or any device it is built on (LVM on LUKS, RAID), is dm-crypt.
func (l linuxProbe) crypt(dev string, depth int) bool {
	if depth > 8 {
		return false
	}
	base := filepath.Join(l.sys, "dev/block", dev)
	if uuid, err := os.ReadFile(filepath.Join(base, "dm/uuid")); err == nil && strings.HasPrefix(string(uuid), "CRYPT-") {
		return true
	}
	slaves, _ := os.ReadDir(filepath.Join(base, "slaves"))
	for _, s := range slaves {
		d, err := os.ReadFile(filepath.Join(base, "slaves", s.Name(), "dev"))
		if err == nil && l.crypt(strings.TrimSpace(string(d)), depth+1) {
			return true
		}
	}
	return false
}
