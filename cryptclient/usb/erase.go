package usb

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"strings"
)

// The layout init-usb can create on an erased stick: an MBR, the raw key area free, and one FAT32
// partition from sector 4096 (2 MiB) to the end for the stick's files (pins, host key, backups).
const (
	freshFirstSector = 4096
	minEraseSize     = 64 << 20 // FAT32 needs some room; any stick sold today is far bigger
)

// FreshLayout zeroes the first 2 MiB of the device (old partition tables, boot sectors and whatever
// was in the key area) and writes an MBR with the one FAT32 partition. The partition itself still has
// to be formatted.
func FreshLayout(w io.WriterAt, size int64) error {
	if size < minEraseSize {
		return fmt.Errorf("the device is too small (%d MiB, need at least %d MiB)", size>>20, minEraseSize>>20)
	}
	zero := make([]byte, freshFirstSector*sectorSize)
	if _, err := w.WriteAt(zero, 0); err != nil {
		return fmt.Errorf("clearing the start of the device: %w", err)
	}

	mbr := make([]byte, sectorSize)
	if _, err := rand.Read(mbr[440:444]); err != nil { // disk signature
		return err
	}
	sectors := uint64(size / sectorSize)
	count := sectors - freshFirstSector
	if count > 0xFFFFFFFF {
		count = 0xFFFFFFFF // an MBR partition ends at 2 TiB
	}
	e := mbr[446:462]
	copy(e[1:4], []byte{0xFE, 0xFF, 0xFF}) // CHS not used: LBA only
	e[4] = 0x0C                            // FAT32 (LBA)
	copy(e[5:8], []byte{0xFE, 0xFF, 0xFF})
	binary.LittleEndian.PutUint32(e[8:], freshFirstSector)
	binary.LittleEndian.PutUint32(e[12:], uint32(count))
	mbr[510], mbr[511] = 0x55, 0xAA
	if _, err := w.WriteAt(mbr, 0); err != nil {
		return fmt.Errorf("writing the partition table: %w", err)
	}
	return nil
}

// PartitionPath is the device node of the first partition: /dev/sdb -> /dev/sdb1, but
// /dev/mmcblk0 -> /dev/mmcblk0p1 (names ending in a digit get a p).
func PartitionPath(devicePath string) string {
	if devicePath != "" && strings.ContainsAny(devicePath[len(devicePath)-1:], "0123456789") {
		return devicePath + "p1"
	}
	return devicePath + "1"
}
