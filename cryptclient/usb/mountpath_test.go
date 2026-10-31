package usb

import (
	"strings"
	"testing"
)

func TestLinuxMountPathFindsTheStickByDeviceNotByLabel(t *testing.T) {
	mounts := `/dev/sda2 / ext4 rw,relatime 0 0
/dev/sdb3 /mnt/other ext4 rw 0 0
/dev/sdb1 /media/matti/MY\040STICK vfat rw,nosuid,nodev 0 0
/dev/sdbb1 /media/matti/WRONG vfat rw 0 0
/dev/mmcblk0p1 /media/matti/SD vfat rw 0 0
`
	cases := map[string]string{
		"/dev/sdb":     "/media/matti/MY STICK", // vfat wins over the earlier ext4 partition
		"/dev/sdc":     "",                      // not mounted: no temp directory
		"/dev/mmcblk0": "/media/matti/SD",
		"/dev/sda":     "/",
	}
	for dev, want := range cases {
		if got := linuxMountPath(strings.NewReader(mounts), dev); got != want {
			t.Errorf("%s: got %q, want %q", dev, got, want)
		}
	}
}

func TestDarwinMountPath(t *testing.T) {
	out := `/dev/disk1s1 on / (apfs, local, journaled)
/dev/disk4s1 on /Volumes/MY STICK (msdos, local, nodev, nosuid, noowners)
/dev/disk41s1 on /Volumes/WRONG (msdos, local)
`
	for dev, want := range map[string]string{
		"/dev/disk4": "/Volumes/MY STICK", "/dev/rdisk4": "/Volumes/MY STICK", "/dev/disk5": "",
	} {
		if got := darwinMountPath(out, dev); got != want {
			t.Errorf("%s: got %q, want %q", dev, got, want)
		}
	}
}
