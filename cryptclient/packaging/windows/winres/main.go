// Command winres writes the Windows resources of the client, its padlock icon and its version
// information, as a .syso object file that go build links into cryptclient.exe and CryptStorage.exe:
//
//	go run ./packaging/windows/winres -version 0.1.0 -o rsrc_windows_amd64.syso
//
// The icon is drawn by the same code as the tray icon (wingui.DrawIcon), so the repository holds
// no image files and nothing is downloaded. Without the .syso the programs work the same, Explorer
// only shows them with the default program icon.
package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"image"
	"image/png"
	"os"
	"regexp"
	"strconv"
	"unicode/utf16"

	"cryptclient/wingui"
)

func main() {
	version := flag.String("version", "0.0.0", "version shown in the file properties (x.y.z; anything else counts as 0.0.0)")
	out := flag.String("o", "rsrc_windows_amd64.syso", "output file")
	arch := flag.String("arch", "amd64", "amd64 or arm64")
	flag.Parse()
	machine, ok := machines[*arch]
	if !ok {
		fmt.Fprintf(os.Stderr, "unknown arch %q\n", *arch)
		os.Exit(2)
	}
	if err := os.WriteFile(*out, build(machine, *version), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// machine type and the relocation type for a 32-bit image-relative address (ADDR32NB)
var machines = map[string][2]uint16{
	"amd64": {0x8664, 3},
	"arm64": {0xAA64, 2},
}

const (
	rtIcon      = 3
	rtGroupIcon = 14
	rtVersion   = 16
	langEnUS    = 0x0409
)

var iconSizes = []int{16, 20, 24, 32, 40, 48, 64, 256}

type resource struct {
	typ, id uint32
	data    []byte
}

// resources lists what goes in, sorted by type and id as the directory needs.
func resources(version string) []resource {
	var res []resource
	group := new(bytes.Buffer)
	le(group, uint16(0), uint16(1), uint16(len(iconSizes))) // GRPICONDIR: reserved, type icon, count
	for i, size := range iconSizes {
		img := wingui.DrawIcon(wingui.App, size)
		var data []byte
		if size >= 256 {
			var b bytes.Buffer
			png.Encode(&b, img) //nolint
			data = b.Bytes()
		} else {
			data = dib(img)
		}
		id := uint16(i + 1)
		res = append(res, resource{rtIcon, uint32(id), data})
		w := uint8(size)
		if size >= 256 {
			w = 0 // 0 means 256
		}
		// GRPICONDIRENTRY: width, height, colours, reserved, planes, bit count, size, id
		le(group, w, w, uint8(0), uint8(0), uint16(1), uint16(32), uint32(len(data)), id)
	}
	res = append(res, resource{rtGroupIcon, 1, group.Bytes()})
	res = append(res, resource{rtVersion, 1, versionInfo(version)})
	return res
}

// dib is an icon image in the classic format: a 32-bit bitmap, bottom row first, of double height
// (the colour image and below it the 1-bit transparency mask).
func dib(img *image.NRGBA) []byte {
	w, h := img.Rect.Dx(), img.Rect.Dy()
	maskStride := ((w + 31) / 32) * 4
	b := new(bytes.Buffer)
	le(b, uint32(40), int32(w), int32(2*h), uint16(1), uint16(32), uint32(0),
		uint32(w*h*4+maskStride*h), int32(0), int32(0), uint32(0), uint32(0))
	for y := h - 1; y >= 0; y-- {
		for x := 0; x < w; x++ {
			c := img.NRGBAAt(x, y)
			b.Write([]byte{c.B, c.G, c.R, c.A})
		}
	}
	for y := h - 1; y >= 0; y-- {
		row := make([]byte, maskStride)
		for x := 0; x < w; x++ {
			if img.NRGBAAt(x, y).A == 0 {
				row[x/8] |= 0x80 >> (x % 8)
			}
		}
		b.Write(row)
	}
	return b.Bytes()
}

// versionInfo is the VS_VERSIONINFO resource: Explorer's file properties, and the name Task
// Manager and the notifications show (FileDescription).
func versionInfo(version string) []byte {
	var v [4]uint16
	if m := regexp.MustCompile(`^v?(\d+)\.(\d+)\.(\d+)`).FindStringSubmatch(version); m != nil {
		for i := 0; i < 3; i++ {
			n, _ := strconv.Atoi(m[i+1])
			v[i] = uint16(n)
		}
	}
	ms, ls := uint32(v[0])<<16|uint32(v[1]), uint32(v[2])<<16|uint32(v[3])
	fixed := new(bytes.Buffer)
	// VS_FIXEDFILEINFO: signature, struct version, file and product version, flags mask, flags,
	// OS (Windows NT), type (application), subtype, date
	le(fixed, uint32(0xFEEF04BD), uint32(0x00010000), ms, ls, ms, ls, uint32(0x3F), uint32(0),
		uint32(0x00040004), uint32(1), uint32(0), uint32(0), uint32(0))
	str := func(k, val string) []byte { return node(k, 1, utf16z(val), true) }
	strings := node("040904B0", 1, nil, false,
		str("CompanyName", "Venomia"),
		str("FileDescription", "CryptStorage"),
		str("FileVersion", version),
		str("LegalCopyright", "AGPL-3.0-only"),
		str("ProductName", "CryptStorage"),
		str("ProductVersion", version),
	)
	translation := new(bytes.Buffer)
	le(translation, uint16(langEnUS), uint16(1200)) // English (US), Unicode
	return node("VS_VERSION_INFO", 0, fixed.Bytes(), false,
		node("StringFileInfo", 1, nil, false, strings),
		node("VarFileInfo", 1, nil, false, node("Translation", 0, translation.Bytes(), false)),
	)
}

// node is one block of the version resource: length, value length, type, key, value, children,
// each part starting on a 4-byte boundary. For text values the value length counts characters.
func node(key string, typ uint16, value []byte, text bool, children ...[]byte) []byte {
	b := new(bytes.Buffer)
	le(b, uint16(0), uint16(0), typ)
	b.Write(utf16z(key))
	pad4(b)
	b.Write(value)
	for _, c := range children {
		pad4(b)
		b.Write(c)
	}
	out := b.Bytes()
	valueLen := len(value)
	if text {
		valueLen /= 2
	}
	binary.LittleEndian.PutUint16(out[0:], uint16(len(out)))
	binary.LittleEndian.PutUint16(out[2:], uint16(valueLen))
	return out
}

func utf16z(s string) []byte {
	b := new(bytes.Buffer)
	for _, u := range utf16.Encode([]rune(s)) {
		le(b, u)
	}
	le(b, uint16(0))
	return b.Bytes()
}

func pad4(b *bytes.Buffer) {
	for b.Len()%4 != 0 {
		b.WriteByte(0)
	}
}

func le(b *bytes.Buffer, vs ...any) {
	for _, v := range vs {
		binary.Write(b, binary.LittleEndian, v) //nolint
	}
}

// build lays the resources out as a COFF object with one .rsrc section: the three-level resource
// directory (type, id, language), the data entries, the data, and one relocation per data entry
// so the linker turns their offsets into addresses in the program.
func build(machine [2]uint16, version string) []byte {
	res := resources(version)
	// group by type, keeping order (resources() already sorts by type, then id)
	var types []uint32
	byType := map[uint32][]resource{}
	for _, r := range res {
		if len(byType[r.typ]) == 0 {
			types = append(types, r.typ)
		}
		byType[r.typ] = append(byType[r.typ], r)
	}
	const dirSize, entrySize, dataEntrySize = 16, 8, 16
	// sizes of the directory part: root, one directory per type, one per resource (its language)
	off := dirSize + len(types)*entrySize
	typeDir := map[uint32]int{}
	for _, t := range types {
		typeDir[t] = off
		off += dirSize + len(byType[t])*entrySize
	}
	langDir := make([]int, len(res))
	for i := range res {
		langDir[i] = off
		off += dirSize + entrySize
	}
	dataEntry := make([]int, len(res))
	for i := range res {
		dataEntry[i] = off
		off += dataEntrySize
	}
	dataOff := make([]int, len(res))
	for i, r := range res {
		off = (off + 7) &^ 7
		dataOff[i] = off
		off += len(r.data)
	}
	sec := make([]byte, (off+3)&^3)
	put32 := func(at int, v uint32) { binary.LittleEndian.PutUint32(sec[at:], v) }
	put16 := func(at int, v uint16) { binary.LittleEndian.PutUint16(sec[at:], v) }
	dir := func(at, ids int) { put16(at+14, uint16(ids)) } // only id entries, no named ones
	const subdir = 0x80000000

	dir(0, len(types))
	for i, t := range types {
		put32(dirSize+i*entrySize, t)
		put32(dirSize+i*entrySize+4, subdir|uint32(typeDir[t]))
	}
	i := 0
	for _, t := range types {
		at := typeDir[t]
		dir(at, len(byType[t]))
		for j, r := range byType[t] {
			put32(at+dirSize+j*entrySize, r.id)
			put32(at+dirSize+j*entrySize+4, subdir|uint32(langDir[i]))
			l := langDir[i]
			dir(l, 1)
			put32(l+dirSize, langEnUS)
			put32(l+dirSize+4, uint32(dataEntry[i])) // a leaf: no subdir bit
			put32(dataEntry[i], uint32(dataOff[i]))  // relocated below
			put32(dataEntry[i]+4, uint32(len(r.data)))
			copy(sec[dataOff[i]:], r.data)
			i++
		}
	}

	const fileHeader, sectionHeader, relocSize, symSize = 20, 40, 10, 18
	secStart := fileHeader + sectionHeader
	relocStart := secStart + len(sec)
	symStart := relocStart + len(res)*relocSize
	b := new(bytes.Buffer)
	// file header: machine, sections, time, symbol table, symbols, optional header size, flags
	le(b, machine[0], uint16(1), uint32(0), uint32(symStart), uint32(1), uint16(0), uint16(0))
	// section header: name, virtual size and address, raw size and offset, relocations, line
	// numbers, counts, characteristics (initialised data, readable)
	b.WriteString(".rsrc\x00\x00\x00")
	le(b, uint32(0), uint32(0), uint32(len(sec)), uint32(secStart), uint32(relocStart), uint32(0),
		uint16(len(res)), uint16(0), uint32(0x40000040))
	b.Write(sec)
	for i := range res {
		le(b, uint32(dataEntry[i]), uint32(0), machine[1]) // address, symbol 0 (.rsrc), type
	}
	// the one symbol: the section itself (static), then an empty string table
	b.WriteString(".rsrc\x00\x00\x00")
	le(b, uint32(0), int16(1), uint16(0), uint8(3), uint8(0))
	le(b, uint32(4))
	return b.Bytes()
}
