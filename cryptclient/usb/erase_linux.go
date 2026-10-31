package usb

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// EraseStick erases the whole device and gives it the layout init-usb needs (FreshLayout), with the
// partition formatted FAT32. Partitions of the device that are mounted are unmounted first; it refuses
// a device that holds a system file system.
func EraseStick(devicePath string) error {
	mkfs, err := findMkfsFAT()
	if err != nil {
		return err
	}
	if err := unmountAll(devicePath); err != nil {
		return err
	}
	// O_EXCL on a block device fails while anything still has it mounted
	f, err := os.OpenFile(devicePath, os.O_RDWR|unix.O_EXCL, 0)
	if err != nil {
		return fmt.Errorf("opening %s for erasing: %w", devicePath, err)
	}
	size, err := f.Seek(0, io.SeekEnd)
	if err == nil {
		err = FreshLayout(f, size)
	}
	if err == nil {
		err = f.Sync()
	}
	if err == nil {
		// tell the kernel about the new partition table
		err = unix.IoctlSetInt(int(f.Fd()), unix.BLKRRPART, 0)
	}
	f.Close()
	if err != nil {
		return fmt.Errorf("erasing %s: %w", devicePath, err)
	}

	part := PartitionPath(devicePath)
	for i := 0; i < 50; i++ { // udev creates the node
		if _, err := os.Stat(part); err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	out, err := exec.Command(mkfs, "-F", "32", "-n", "CRYPTSTORE", part).CombinedOutput()
	if err != nil {
		return fmt.Errorf("formatting %s: %v\n%s", part, err, out)
	}
	return nil
}

func findMkfsFAT() (string, error) {
	for _, name := range []string{"mkfs.vfat", "mkfs.fat"} {
		if p, err := exec.LookPath(name); err == nil {
			return p, nil
		}
		for _, dir := range []string{"/usr/sbin", "/sbin"} { // not always in a user's PATH
			p := filepath.Join(dir, name)
			if _, err := os.Stat(p); err == nil {
				return p, nil
			}
		}
	}
	return "", fmt.Errorf("formatting needs mkfs.vfat. On Ubuntu or Debian: sudo apt install dosfstools")
}

// systemMounts are file systems that must never be on a stick that gets erased.
var systemMounts = map[string]bool{"/": true, "/boot": true, "/boot/efi": true, "/home": true, "/usr": true, "/var": true}

func unmountAll(devicePath string) error {
	f, err := os.Open("/proc/mounts")
	if err != nil {
		return err
	}
	defer f.Close()
	var targets []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 2 || !strings.HasPrefix(fields[0], devicePath) {
			continue
		}
		rest := strings.TrimPrefix(strings.TrimPrefix(fields[0], devicePath), "p")
		if rest != "" && strings.Trim(rest, "0123456789") != "" {
			continue // /dev/sdb must not match /dev/sdba1
		}
		mnt := strings.ReplaceAll(fields[1], `\040`, " ")
		if systemMounts[mnt] {
			return fmt.Errorf("%s holds %s of this computer; refusing to erase it", fields[0], mnt)
		}
		targets = append(targets, mnt)
	}
	for _, mnt := range targets {
		if out, err := exec.Command("umount", mnt).CombinedOutput(); err != nil {
			return fmt.Errorf("could not unmount %s (close the files and windows that use the stick): %s",
				mnt, strings.TrimSpace(string(out)))
		}
	}
	return nil
}
