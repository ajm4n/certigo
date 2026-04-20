package main

import "os"

// readFile is a thin wrapper used by cobra subcommands that need to load
// a file into memory (PFX, PEM, backup JSON, etc.).
func readFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}

// writeFile writes data to path with 0o600 permissions.
func writeFile(path string, data []byte) error {
	return os.WriteFile(path, data, 0o600)
}
