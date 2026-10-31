package main

import (
	"bytes"
	"encoding/binary"
	"image/png"
	"testing"
)

// TestBuild walks the resource directory of the object file as Windows will and checks that every
// leaf points at its data, with a relocation for each.
func TestBuild(t *testing.T) {
	obj := build(machines["amd64"], "1.2.3")
	u16 := func(b []byte, o uint32) uint16 { return binary.LittleEndian.Uint16(b[o:]) }
	u32 := func(b []byte, o uint32) uint32 { return binary.LittleEndian.Uint32(b[o:]) }
	if u16(obj, 0) != 0x8664 || u16(obj, 2) != 1 {
		t.Fatalf("bad file header")
	}
	if string(obj[20:25]) != ".rsrc" {
		t.Fatalf("section is %q", obj[20:28])
	}
	size, start, nreloc := u32(obj, 20+16), u32(obj, 20+20), u32(obj, 20+24)
	sec := obj[start : start+size]
	relocs := map[uint32]bool{}
	for i := uint32(0); i < uint32(u16(obj, 20+32)); i++ {
		relocs[u32(obj, nreloc+i*10)] = true
	}
	leaves := map[uint32]int{}
	var walk func(o uint32, path []uint32)
	walk = func(o uint32, path []uint32) {
		n := uint32(u16(sec, o+12)) + uint32(u16(sec, o+14))
		for i := uint32(0); i < n; i++ {
			e := o + 16 + i*8
			id, off := u32(sec, e), u32(sec, e+4)
			p := append(append([]uint32{}, path...), id)
			if off&0x80000000 != 0 {
				walk(off&0x7fffffff, p)
				continue
			}
			if len(p) != 3 || !relocs[off] {
				t.Errorf("leaf %v at %d: depth %d, relocated %v", p, off, len(p), relocs[off])
			}
			data := sec[u32(sec, off) : u32(sec, off)+u32(sec, off+4)]
			leaves[p[0]]++
			switch {
			case p[0] == rtIcon && bytes.HasPrefix(data, []byte("\x89PNG")):
				if img, err := png.Decode(bytes.NewReader(data)); err != nil || img.Bounds().Dx() != 256 {
					t.Errorf("png icon: %v", err)
				}
			case p[0] == rtIcon:
				w, h := int32(u32(data, 4)), int32(u32(data, 8))
				if h != 2*w || u32(data, 0) != 40 {
					t.Errorf("dib icon %dx%d", w, h)
				}
			case p[0] == rtGroupIcon:
				if int(u16(data, 4)) != len(iconSizes) {
					t.Errorf("group has %d icons", u16(data, 4))
				}
			case p[0] == rtVersion:
				if !bytes.Contains(data, utf16z("FileDescription")) || u32(data, 40) != 0xFEEF04BD ||
					u32(data, 48) != 1<<16|2 || u32(data, 52) != 3<<16 {
					t.Errorf("version resource wrong")
				}
			}
		}
	}
	walk(0, nil)
	if leaves[rtIcon] != len(iconSizes) || leaves[rtGroupIcon] != 1 || leaves[rtVersion] != 1 || len(relocs) != len(iconSizes)+2 {
		t.Errorf("leaves %v, relocations %d", leaves, len(relocs))
	}
}
