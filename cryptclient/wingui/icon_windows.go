package wingui

import (
	"errors"
	"image"
	"unsafe"
)

// Icon makes a Windows icon of the padlock at the size of the notification area.
func Icon(state IconState) (uintptr, error) {
	setup()
	size := 16
	if s, _, _ := pGetSystemMetrics.Call(smCxSmIcon); s > 0 {
		size = int(s)
	}
	return hicon(DrawIcon(state, size))
}

// FreeIcon releases an icon made by Icon.
func FreeIcon(h uintptr) {
	if h != 0 {
		pDestroyIcon.Call(h) //nolint
	}
}

func hicon(img *image.NRGBA) (uintptr, error) {
	w, h := img.Rect.Dx(), img.Rect.Dy()
	type bitmapInfoHeader struct {
		Size                   uint32
		Width, Height          int32
		Planes, BitCount       uint16
		Compression, SizeImage uint32
		XPelsPerM, YPelsPerM   int32
		ClrUsed, ClrImportant  uint32
	}
	bi := bitmapInfoHeader{Width: int32(w), Height: -int32(h), Planes: 1, BitCount: 32} // negative height: top row first
	bi.Size = uint32(unsafe.Sizeof(bi))
	var bits unsafe.Pointer
	color, _, _ := pCreateDIBSection.Call(0, uintptr(unsafe.Pointer(&bi)), 0, uintptr(unsafe.Pointer(&bits)), 0, 0)
	if color == 0 || bits == nil {
		return 0, errors.New("CreateDIBSection failed")
	}
	defer pDeleteObject.Call(color) //nolint
	dst := unsafe.Slice((*byte)(bits), w*h*4)
	for i := 0; i < w*h; i++ { // RGBA → BGRA
		p := img.Pix[i*4 : i*4+4]
		dst[i*4], dst[i*4+1], dst[i*4+2], dst[i*4+3] = p[2], p[1], p[0], p[3]
	}
	mask, _, _ := pCreateBitmap.Call(uintptr(w), uintptr(h), 1, 1, 0)
	if mask == 0 {
		return 0, errors.New("CreateBitmap failed")
	}
	defer pDeleteObject.Call(mask) //nolint
	type iconInfo struct {
		Icon               int32
		XHotspot, YHotspot uint32
		Mask, Color        uintptr
	}
	ii := iconInfo{Icon: 1, Mask: mask, Color: color}
	hi, _, err := pCreateIconIndirect.Call(uintptr(unsafe.Pointer(&ii)))
	if hi == 0 {
		return 0, err
	}
	return hi, nil
}
