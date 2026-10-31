package wingui

import (
	"image"
	"image/color"
	"math"
)

// The tray icon is drawn here rather than shipped as a file: a padlock, closed and grey when the
// storage is not open, open and green when it is, amber while connecting.

// IconState is what the icon shows.
type IconState int

const (
	Disconnected IconState = iota
	Connecting
	Connected
	// App is the program's own icon in Explorer and the Start menu: closed, in blue.
	App
)

func (s IconState) colour() color.NRGBA {
	switch s {
	case Connected:
		return color.NRGBA{0x2E, 0x7D, 0x32, 0xFF}
	case Connecting:
		return color.NRGBA{0xEF, 0x8F, 0x00, 0xFF}
	case App:
		return color.NRGBA{0x15, 0x65, 0xC0, 0xFF}
	}
	return color.NRGBA{0x54, 0x6E, 0x7A, 0xFF}
}

// DrawIcon draws the padlock at size × size pixels.
func DrawIcon(state IconState, size int) *image.NRGBA {
	img := image.NewNRGBA(image.Rect(0, 0, size, size))
	body := state.colour()
	shackle := color.NRGBA{0x78, 0x90, 0x9C, 0xFF} // light enough for a dark taskbar too
	if state == Connected {
		shackle = body
	}
	lift := 0.0
	if state == Connected {
		lift = 0.12 // the shackle pulled up: open
	}
	const sub = 4 // sub-samples per pixel side, for smooth edges
	for py := 0; py < size; py++ {
		for px := 0; px < size; px++ {
			var nBody, nShackle, nHole int
			for sy := 0; sy < sub; sy++ {
				for sx := 0; sx < sub; sx++ {
					x := (float64(px) + (float64(sx)+0.5)/sub) / float64(size)
					y := (float64(py) + (float64(sy)+0.5)/sub) / float64(size)
					switch {
					case inRoundRect(x, y, 0.14, 0.44, 0.86, 0.96, 0.10):
						if inKeyhole(x, y) {
							nHole++
						} else {
							nBody++
						}
					case inShackle(x, y, lift, state == Connected):
						nShackle++
					}
				}
			}
			total := float64(sub * sub)
			switch {
			case nBody+nHole > 0:
				a := float64(nBody+nHole) / total
				c := mix(body, color.NRGBA{0xFF, 0xFF, 0xFF, 0xFF}, float64(nHole)/float64(nBody+nHole))
				c.A = uint8(math.Round(a * 255))
				img.SetNRGBA(px, py, c)
			case nShackle > 0:
				c := shackle
				c.A = uint8(math.Round(float64(nShackle) / total * 255))
				img.SetNRGBA(px, py, c)
			}
		}
	}
	return img
}

func inRoundRect(x, y, x0, y0, x1, y1, r float64) bool {
	if x < x0 || x > x1 || y < y0 || y > y1 {
		return false
	}
	cx := math.Min(math.Max(x, x0+r), x1-r)
	cy := math.Min(math.Max(y, y0+r), y1-r)
	return (x-cx)*(x-cx)+(y-cy)*(y-cy) <= r*r
}

// inShackle is the U-shaped bar above the body; open, its right leg leaves the body.
func inShackle(x, y, lift float64, open bool) bool {
	const cx, outer, inner = 0.5, 0.30, 0.18
	cy := 0.36 - lift
	legBottom := 0.46
	if y <= cy {
		d := math.Hypot(x-cx, y-cy)
		return d <= outer && d >= inner
	}
	if y > legBottom {
		return false
	}
	left := x >= cx-outer && x <= cx-inner
	right := x >= cx+inner && x <= cx+outer
	if open {
		right = right && y <= cy+0.04
	}
	return left || right
}

func inKeyhole(x, y float64) bool {
	if math.Hypot(x-0.5, y-0.64) <= 0.075 {
		return true
	}
	return x >= 0.47 && x <= 0.53 && y >= 0.64 && y <= 0.82
}

func mix(a, b color.NRGBA, t float64) color.NRGBA {
	l := func(p, q uint8) uint8 { return uint8(math.Round(float64(p)*(1-t) + float64(q)*t)) }
	return color.NRGBA{l(a.R, b.R), l(a.G, b.G), l(a.B, b.B), a.A}
}
