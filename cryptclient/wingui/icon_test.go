package wingui

import "testing"

func TestDrawIcon(t *testing.T) {
	for _, size := range []int{16, 20, 24, 32} {
		for _, s := range []IconState{Disconnected, Connecting, Connected, App} {
			img := DrawIcon(s, size)
			if b := img.Bounds(); b.Dx() != size || b.Dy() != size {
				t.Fatalf("size %d: got %v", size, b)
			}
			if c := img.NRGBAAt(0, 0); c.A != 0 {
				t.Errorf("size %d state %d: corner not transparent: %v", size, s, c)
			}
			// the body, left of the keyhole
			if c := img.NRGBAAt(size*3/10, size*3/4); c.A != 255 || c != s.colour() {
				t.Errorf("size %d state %d: body pixel %v, want %v", size, s, c, s.colour())
			}
		}
	}
	if DrawIcon(Connected, 16).NRGBAAt(4, 12) == DrawIcon(Disconnected, 16).NRGBAAt(4, 12) {
		t.Error("connected and disconnected look the same")
	}
}
