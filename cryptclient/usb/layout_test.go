package usb

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
)

const imageSize = 8 << 20 // 8 MiB is plenty: the key area ends near 1.05 MiB

type image struct{ b []byte }

func newImage() *image { return &image{make([]byte, imageSize)} }

func (im *image) reader() *bytes.Reader { return bytes.NewReader(im.b) }

func (im *image) mbr(parts ...[3]uint32) *image { // {type, firstLBA, sectors}
	im.b[510], im.b[511] = 0x55, 0xAA
	for i, p := range parts {
		e := im.b[446+16*i:]
		e[4] = byte(p[0])
		binary.LittleEndian.PutUint32(e[8:], p[1])
		binary.LittleEndian.PutUint32(e[12:], p[2])
	}
	return im
}

// gpt writes a protective MBR plus a minimal GPT with the given partitions {first, last} LBA.
func (im *image) gpt(parts ...[2]uint64) *image {
	im.mbr([3]uint32{0xEE, 1, 0xFFFFFFFF})
	h := im.b[512:]
	copy(h, "EFI PART")
	binary.LittleEndian.PutUint64(h[72:], 2) // entries at LBA 2
	binary.LittleEndian.PutUint32(h[80:], 128)
	binary.LittleEndian.PutUint32(h[84:], 128)
	for i, p := range parts {
		e := im.b[1024+128*i:]
		copy(e, []byte{0xAF, 0x3D, 0xC6, 0x0F, 0x83, 0x84, 0x72, 0x47, 0x8E, 0x79, 0x3D, 0x69, 0xD8, 0x47, 0x7D, 0xE4})
		binary.LittleEndian.PutUint64(e[32:], p[0])
		binary.LittleEndian.PutUint64(e[40:], p[1])
	}
	return im
}

func wantConflict(t *testing.T, im *image, why string) {
	t.Helper()
	err := CheckRawAreaFree(im.reader(), int64(len(im.b)))
	var le *LayoutError
	if !errors.As(err, &le) {
		t.Fatalf("%s: expected a layout conflict, got %v", why, err)
	}
}

func wantFree(t *testing.T, im *image, why string) {
	t.Helper()
	if err := CheckRawAreaFree(im.reader(), int64(len(im.b))); err != nil {
		t.Fatalf("%s: expected the area to be free, got %v", why, err)
	}
}

func TestBlankDeviceIsFree(t *testing.T) { wantFree(t, newImage(), "blank device") }

// The ordinary case that used to be corrupted: a FAT32 partition at the usual 1 MiB offset.
func TestFirstPartitionAtTheUsualOffsetIsAConflict(t *testing.T) {
	wantConflict(t, newImage().mbr([3]uint32{0x0C, 2048, 14000}), "FAT32 partition at sector 2048")
}

func TestPartitionAfterTheGapIsFree(t *testing.T) {
	wantFree(t, newImage().mbr([3]uint32{0x0C, 4096, 10000}), "partition starting at sector 4096")
}

func TestPartitionBoundaries(t *testing.T) {
	wantFree(t, newImage().mbr([3]uint32{0x0C, 63, 1985}), "partition ending right before the area (sectors 63-2047)")
	wantConflict(t, newImage().mbr([3]uint32{0x0C, 63, 1986}), "partition reaching sector 2048")
	wantConflict(t, newImage().mbr([3]uint32{0x0C, 63, 100000}), "partition spanning the area")
	wantFree(t, newImage().mbr([3]uint32{0x0C, uint32(rawAreaLastSector), 5000}), "partition starting right after the area")
	wantConflict(t, newImage().mbr([3]uint32{0x0C, uint32(rawAreaLastSector - 1), 5000}), "partition starting inside the area")
	wantConflict(t, newImage().mbr([3]uint32{0, 0, 0}, [3]uint32{0x83, 2048, 100}), "second partition entry is checked too")
}

func TestGPT(t *testing.T) {
	wantConflict(t, newImage().gpt([2]uint64{2048, 14000}), "GPT partition at sector 2048")
	wantFree(t, newImage().gpt([2]uint64{4096, 14000}), "GPT partition at sector 4096")
	wantFree(t, newImage().gpt(), "empty GPT")
	im := newImage().mbr([3]uint32{0xEE, 1, 0xFFFFFFFF}) // protective MBR without a header
	wantConflict(t, im, "protective MBR without GPT header")
}

func TestFilesystemWithoutPartitionTable(t *testing.T) {
	fat := newImage()
	fat.b[510], fat.b[511] = 0x55, 0xAA
	copy(fat.b[82:], "FAT32   ")
	wantConflict(t, fat, "superfloppy FAT32")

	ntfs := newImage()
	ntfs.b[510], ntfs.b[511] = 0x55, 0xAA
	copy(ntfs.b[3:], "NTFS    ")
	wantConflict(t, ntfs, "superfloppy NTFS")
}

func TestUnknownDataInTheAreaIsAConflict(t *testing.T) {
	im := newImage()
	im.b[MagicOffset+100] = 7
	wantConflict(t, im, "non-zero data at sector 2048")
	im = newImage()
	im.b[KeyOffset+KeySize-1] = 1
	wantConflict(t, im, "non-zero data at the end of the area")
}

func TestStickAlreadyPreparedByInitUSBMayBeReinitialised(t *testing.T) {
	im := newImage().mbr([3]uint32{0x0C, 2048, 14000}) // would conflict ...
	copy(im.b[MagicOffset:], MagicBytes)               // ... but our magic is there
	wantFree(t, im, "stick carrying our magic")
}

func TestDeviceTooSmallOrUnreadable(t *testing.T) {
	small := make([]byte, 512*1024)
	if err := CheckRawAreaFree(bytes.NewReader(small), int64(len(small))); err == nil {
		t.Fatal("a device smaller than the key area was accepted")
	}
	if err := CheckRawAreaFree(bytes.NewReader(make([]byte, 100)), imageSize); err == nil {
		t.Fatal("an unreadable device was accepted")
	}
}

func TestErrorTellsTheUserWhatToDo(t *testing.T) {
	err := CheckRawAreaFree(newImage().mbr([3]uint32{0x0C, 2048, 14000}).reader(), imageSize)
	if err == nil || !bytes.Contains([]byte(err.Error()), []byte("sector\n4096")) && !bytes.Contains([]byte(err.Error()), []byte("4096")) {
		t.Fatalf("the error should explain how to repartition: %v", err)
	}
}
