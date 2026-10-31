package diskenc

import (
	"os"
	"path/filepath"
	"testing"
)

// fakeSys builds a /sys/dev/block tree: nvme0n1p3 (259:3) under LUKS (253:0) under LVM root (253:1),
// and a plain partition sda1 (8:1).
func fakeSys(t *testing.T) string {
	sys := t.TempDir()
	dev := func(id string, files map[string]string) {
		for name, body := range files {
			p := filepath.Join(sys, "dev/block", id, name)
			if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	dev("259:3", map[string]string{"dev": "259:3\n"})
	dev("253:0", map[string]string{"dev": "253:0\n", "dm/uuid": "CRYPT-LUKS2-0123abcd-luks\n"})
	dev("253:1", map[string]string{"dev": "253:1\n", "dm/uuid": "LVM-xyz\n"})
	dev("8:1", map[string]string{"dev": "8:1\n"})
	// slaves are links to the device directories in sysfs; a directory with a dev file is enough here
	dev("253:1", map[string]string{"slaves/dm-0/dev": "253:0\n"})
	dev("253:0", map[string]string{"slaves/nvme0n1p3/dev": "259:3\n"})
	return sys
}

const mountinfo = `22 1 253:1 / / rw,relatime shared:1 - ext4 /dev/mapper/vg-root rw
30 22 8:1 / /data rw,relatime shared:2 - ext4 /dev/sda1 rw
31 22 0:40 / /home/me/My\040Files rw - btrfs /dev/sda1 rw
32 22 0:41 / /tmp rw - tmpfs tmpfs rw
33 22 0:42 / /mnt/nas rw - fuse.sshfs me@nas: rw
34 22 0:43 / /home/me/Private rw - ecryptfs /home/me/.Private rw
`

func probe(t *testing.T) linuxProbe {
	mi := filepath.Join(t.TempDir(), "mountinfo")
	if err := os.WriteFile(mi, []byte(mountinfo), 0o644); err != nil {
		t.Fatal(err)
	}
	return linuxProbe{mountinfo: mi, sys: fakeSys(t), rdev: func(p string) (string, bool) {
		if p == "/dev/sda1" {
			return "8:1", true
		}
		return "", false
	}}
}

func TestLinux(t *testing.T) {
	l := probe(t)
	for path, want := range map[string]State{
		"/home/me/CryptStorage":          Encrypted,    // LVM on LUKS, found through the slaves
		"/data/CryptStorage":             NotEncrypted, // plain partition
		"/datax":                         Encrypted,    // not under /data: the root file system
		"/home/me/My Files/CryptStorage": NotEncrypted, // btrfs: the anonymous 0:40 is resolved through the source
		"/tmp/x":                         Unknown,
		"/mnt/nas/CryptStorage":          Unknown,
		"/home/me/Private/CryptStorage":  Encrypted,
	} {
		if got := l.check(path); got.State != want {
			t.Errorf("%s: got %v (%s), want %v", path, got.State, got.Detail, want)
		}
	}
}

func TestCheckThisMachine(t *testing.T) {
	// whatever the machine has, the check must not fail on a folder that does not exist yet
	r := Check(filepath.Join(t.TempDir(), "not", "yet"))
	t.Logf("this machine: %v (%s)", r.State, r.Detail)
}
