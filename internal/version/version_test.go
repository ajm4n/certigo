package version

import "testing"

func TestVersionIsNonEmpty(t *testing.T) {
	if Version == "" {
		t.Fatal("Version must not be empty; defaults to \"dev\" at build time")
	}
}
