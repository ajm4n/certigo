package account

import (
	"testing"
)

func TestUnicodePwd(t *testing.T) {
	const pwd = "P@ssw0rd!"
	got := UnicodePwd(pwd)

	// UTF-16LE of `"<pwd>"` - ASCII-only, so each rune is 2 bytes.
	wantLen := 2 * (len(pwd) + 2)
	if len(got) != wantLen {
		t.Fatalf("UnicodePwd(%q) len=%d, want %d", pwd, len(got), wantLen)
	}

	// First two bytes must be the opening quote: 0x22 0x00.
	if got[0] != 0x22 || got[1] != 0x00 {
		t.Errorf("leading bytes = %#x %#x, want 0x22 0x00", got[0], got[1])
	}
	// Last two bytes must be the closing quote: 0x22 0x00.
	n := len(got)
	if got[n-2] != 0x22 || got[n-1] != 0x00 {
		t.Errorf("trailing bytes = %#x %#x, want 0x22 0x00", got[n-2], got[n-1])
	}

	// Spot-check a known ASCII rune - 'P' at offset 2 should be 0x50 0x00.
	if got[2] != 0x50 || got[3] != 0x00 {
		t.Errorf("byte[2:4] = %#x %#x, want 0x50 0x00 ('P')", got[2], got[3])
	}
}

func TestUnicodePwd_Empty(t *testing.T) {
	got := UnicodePwd("")
	// `""` - two ASCII quotes, each 2 bytes in UTF-16LE.
	if len(got) != 4 {
		t.Fatalf("UnicodePwd(\"\") len=%d, want 4", len(got))
	}
	want := []byte{0x22, 0x00, 0x22, 0x00}
	for i, b := range want {
		if got[i] != b {
			t.Errorf("byte %d = %#x, want %#x", i, got[i], b)
		}
	}
}
