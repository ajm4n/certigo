// Command certigo is a pure-Go 1:1 port of Certipy.
//
// Run `certigo --help` for usage.
package main

import (
	"fmt"
	"os"
)

func main() {
	if err := NewRootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
