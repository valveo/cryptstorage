package usb

import "testing"

func TestFreshLayoutFreesTheKeyArea(t *testing.T) {
	const size = minEraseSize
	im := &image{make([]byte, size)}
	// an ordinary stick: one FAT32 partition from sector 2048, data in the key area
	im.mbr([3]uint32{0x0C, 2048, size/512 - 2048})
	im.b[MagicOffset+3] = 0x42
	wantConflict(t, im, "before erasing")

	if err := FreshLayout(writerAt(im.b), size); err != nil {
		t.Fatal(err)
	}
	wantFree(t, im, "after erasing")
	if im.b[446+4] != 0x0C || im.b[510] != 0x55 || im.b[511] != 0xAA {
		t.Fatal("no FAT32 partition entry")
	}
}

func TestFreshLayoutTooSmall(t *testing.T) {
	b := make([]byte, 8<<20)
	if err := FreshLayout(writerAt(b), int64(len(b))); err == nil {
		t.Fatal("an 8 MiB device was accepted")
	}
}

func TestPartitionPath(t *testing.T) {
	for in, want := range map[string]string{"/dev/sdb": "/dev/sdb1", "/dev/mmcblk0": "/dev/mmcblk0p1", "/dev/loop3": "/dev/loop3p1"} {
		if got := PartitionPath(in); got != want {
			t.Errorf("%s: got %s, want %s", in, got, want)
		}
	}
}

type writerAt []byte

func (w writerAt) WriteAt(p []byte, off int64) (int, error) { return copy(w[off:], p), nil }
