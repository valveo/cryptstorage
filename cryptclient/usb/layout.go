package usb

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"runtime"
)

const sectorSize = 512

// The area WriteEncryptedKey overwrites: from the magic bytes at MagicOffset (sector
// 2048, 1 MiB into the device) through the end of the key blob.
const (
	rawAreaFirstSector = uint64(MagicOffset / sectorSize)
	rawAreaEnd         = KeyOffset + KeySize // byte offset, exclusive
	rawAreaLastSector  = uint64((rawAreaEnd + sectorSize - 1) / sectorSize)
)

// LayoutError means writing the key would damage data that is already on the stick.
type LayoutError struct{ Reason string }

func (e *LayoutError) Error() string {
	return e.Reason + "\n\n" +
		"Writing the key there would corrupt it. The key is stored in raw sectors, so it needs a gap\n" +
		"that no partition uses: repartition the stick so that the first partition starts at sector\n" +
		"4096 (2 MiB) or later, e.g. in fdisk/parted set the first sector of the new partition to 4096,\n" +
		"then run init-usb again. Everything on the stick is lost when it is repartitioned."
}

func conflict(format string, args ...interface{}) error {
	return &LayoutError{Reason: fmt.Sprintf(format, args...)}
}

// overlapsRawArea reports whether [first, first+count) sectors touch the raw key area.
func overlapsRawArea(first, count uint64) bool {
	if count == 0 {
		return false
	}
	return first < rawAreaLastSector && first+count > rawAreaFirstSector
}

// CheckRawArea refuses to proceed when the key area collides with a partition or
// filesystem. The area is 1 MiB into the device, which is exactly where the first
// partition of an ordinarily formatted USB stick begins (its boot sector or FAT tables).
func CheckRawArea(devicePath string) error {
	if runtime.GOOS == "windows" {
		return nil // the key is a file on the stick's drive there, not raw sectors
	}
	f, err := os.Open(devicePath)
	if err != nil {
		return fmt.Errorf("opening %s: %w", devicePath, err)
	}
	defer f.Close()
	size, err := f.Seek(0, io.SeekEnd)
	if err != nil {
		return fmt.Errorf("determining the size of %s: %w", devicePath, err)
	}
	return CheckRawAreaFree(f, size)
}

// CheckRawAreaFree is CheckRawArea on any ReaderAt (testable without a device).
func CheckRawAreaFree(r io.ReaderAt, deviceSize int64) error {
	if deviceSize < rawAreaEnd {
		return fmt.Errorf("the device is too small (%d bytes, need at least %d)", deviceSize, rawAreaEnd)
	}

	// A stick prepared by init-usb earlier carries our magic: re-initialising is fine.
	magic := make([]byte, len(MagicBytes))
	if _, err := r.ReadAt(magic, MagicOffset); err == nil && bytes.Equal(magic, MagicBytes) {
		return nil
	}

	sector0 := make([]byte, sectorSize)
	if _, err := r.ReadAt(sector0, 0); err != nil {
		return fmt.Errorf("reading the first sector: %w", err)
	}
	hasSignature := sector0[510] == 0x55 && sector0[511] == 0xAA

	// No partition table at all: a filesystem straight on the device ("superfloppy")
	if hasSignature {
		for _, fs := range []struct {
			off  int
			sig  string
			name string
		}{
			{82, "FAT32   ", "FAT32"}, {54, "FAT16   ", "FAT16"}, {54, "FAT12   ", "FAT12"},
			{3, "NTFS    ", "NTFS"}, {3, "EXFAT   ", "exFAT"},
		} {
			if string(sector0[fs.off:fs.off+len(fs.sig)]) == fs.sig {
				return conflict("The whole device is one %s filesystem (no partition table).", fs.name)
			}
		}
	}

	if hasSignature {
		gpt := false
		for i := 0; i < 4; i++ {
			e := sector0[446+16*i : 446+16*i+16]
			ptype, first, count := e[4], uint64(binary.LittleEndian.Uint32(e[8:])), uint64(binary.LittleEndian.Uint32(e[12:]))
			if ptype == 0xEE {
				gpt = true
				continue
			}
			if ptype != 0 && overlapsRawArea(first, count) {
				return conflict("Partition %d (type 0x%02x, sectors %d-%d) covers the sector where the key would be written.",
					i+1, ptype, first, first+count-1)
			}
		}
		if gpt {
			if err := checkGPT(r); err != nil {
				return err
			}
		}
	}

	// Whatever is there, if it is not zeros it is somebody's data
	area := make([]byte, rawAreaEnd-MagicOffset)
	if _, err := r.ReadAt(area, MagicOffset); err != nil {
		return fmt.Errorf("reading the key area: %w", err)
	}
	if !allZero(area) {
		return conflict("The sectors where the key would be written (%d-%d) already contain data.",
			rawAreaFirstSector, rawAreaLastSector-1)
	}
	return nil
}

func checkGPT(r io.ReaderAt) error {
	hdr := make([]byte, sectorSize)
	if _, err := r.ReadAt(hdr, sectorSize); err != nil {
		return fmt.Errorf("reading the GPT header: %w", err)
	}
	if string(hdr[:8]) != "EFI PART" {
		return conflict("The device has a protective MBR but no valid GPT header.")
	}
	entriesLBA := binary.LittleEndian.Uint64(hdr[72:])
	count := binary.LittleEndian.Uint32(hdr[80:])
	entrySize := binary.LittleEndian.Uint32(hdr[84:])
	if count == 0 || count > 1024 || entrySize < 128 || entrySize > 4096 {
		return conflict("The GPT partition table looks damaged.")
	}
	table := make([]byte, int(count)*int(entrySize))
	if _, err := r.ReadAt(table, int64(entriesLBA)*sectorSize); err != nil {
		return fmt.Errorf("reading the GPT partition entries: %w", err)
	}
	for i := 0; i < int(count); i++ {
		e := table[i*int(entrySize) : (i+1)*int(entrySize)]
		if allZero(e[:16]) { // unused entry
			continue
		}
		first, last := binary.LittleEndian.Uint64(e[32:]), binary.LittleEndian.Uint64(e[40:])
		if last >= first && overlapsRawArea(first, last-first+1) {
			return conflict("GPT partition %d (sectors %d-%d) covers the sector where the key would be written.", i+1, first, last)
		}
	}
	return nil
}

func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}
