package main

import (
	"fmt"
	"io"
	"os"
)

// progress is a tiny stderr-bound status reporter modelled on certipy's
// "[*] doing X ... [+] result" style. Lines are prefixed with one of:
//
//	[*]   informational progress    (cyan)
//	[+]   success result            (green)
//	[!]   warning                   (yellow)
//
// Colors are only emitted when the sink is a terminal. Non-tty callers
// (pipes, logs, CI captures) get plain text.
type progress struct {
	w     io.Writer
	color bool
}

func newProgress(w io.Writer) *progress {
	return &progress{w: w, color: isStderrTTY(w)}
}

func isStderrTTY(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}

const (
	clrReset  = "\x1b[0m"
	clrCyan   = "\x1b[36m"
	clrGreen  = "\x1b[32m"
	clrYellow = "\x1b[33m"
)

func (p *progress) tag(prefix, col string) string {
	if !p.color {
		return prefix
	}
	return col + prefix + clrReset
}

// Infof prints a progress line.
func (p *progress) Infof(format string, args ...any) {
	_, _ = fmt.Fprintf(p.w, "%s %s\n", p.tag("[*]", clrCyan), fmt.Sprintf(format, args...))
}

// OKf prints a success line.
func (p *progress) OKf(format string, args ...any) {
	_, _ = fmt.Fprintf(p.w, "%s %s\n", p.tag("[+]", clrGreen), fmt.Sprintf(format, args...))
}

// Warnf prints a warning line.
func (p *progress) Warnf(format string, args ...any) {
	_, _ = fmt.Fprintf(p.w, "%s %s\n", p.tag("[!]", clrYellow), fmt.Sprintf(format, args...))
}

// plural returns the singular form when n == 1, else the plural form.
func plural(n int, singular, pluralForm string) string {
	if n == 1 {
		return singular
	}
	return pluralForm
}
