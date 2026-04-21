package output

import (
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/ajm4n/certigo/internal/adcs"
)

// ansiRE matches any CSI escape sequence (\x1b[...m, etc.). Used by
// ansiWidth to compute a cell's *visible* character count so padding
// lines up when columns contain colored values. text/tabwriter does not
// do this - it counts raw bytes, which inflates column widths whenever
// colors are present and misaligns the output.
var ansiRE = regexp.MustCompile(`\x1b\[[0-9;]*m`)

// ansiWidth returns the display width of s (raw-byte length minus any
// CSI escape sequences). Assumes single-byte runes, which is fine for
// the ASCII text this formatter emits.
func ansiWidth(s string) int {
	return len(ansiRE.ReplaceAllString(s, ""))
}

// padRight returns s followed by enough spaces so the visible width
// matches width. Panics on negative padding would be a bug; the caller
// controls width.
func padRight(s string, width int) string {
	gap := width - ansiWidth(s)
	if gap <= 0 {
		return s
	}
	return s + strings.Repeat(" ", gap)
}

// ANSI escape codes used for styling the short output. Only emitted when
// the target writer is a terminal; piping to a file or another process
// gets plain text so downstream tooling isn't confused by escape sequences.
const (
	ansiReset    = "\x1b[0m"
	ansiBold     = "\x1b[1m"
	ansiDim      = "\x1b[2m"
	ansiRed      = "\x1b[31m"
	ansiGreen    = "\x1b[32m"
	ansiYellow   = "\x1b[33m"
	ansiBlue     = "\x1b[34m"
	ansiCyan     = "\x1b[36m"
	ansiBoldCyan = "\x1b[1;36m"
)

func isTerm(w io.Writer) bool {
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

// header returns s wrapped in bold-cyan when tty is true.
func header(s string, tty bool) string {
	if !tty {
		return s
	}
	return ansiBoldCyan + s + ansiReset
}

// boolCell renders a yes/no value with green/grey when on a tty.
func boolCell(v bool, tty bool) string {
	if !tty {
		return yesNoShort(v)
	}
	if v {
		return ansiGreen + "yes" + ansiReset
	}
	return ansiDim + "no" + ansiReset
}

// escCell renders the ESC list in red when there are findings, dim dash
// otherwise. Non-tty output is plain.
func escCell(findings []adcs.Finding, tty bool) string {
	if len(findings) == 0 {
		if tty {
			return ansiDim + "-" + ansiReset
		}
		return "-"
	}
	s := escKinds(findings)
	if !tty {
		return s
	}
	return ansiRed + s + ansiReset
}

// ShortFormatter emits a compact one-line-per-template summary table plus
// a short CA section. Useful for scripting and for triage scans where the
// full Certipy-style dump is too noisy.
type ShortFormatter struct{}

// Name implements Formatter.
func (ShortFormatter) Name() string { return "short" }

func init() { register(ShortFormatter{}) }

// Format writes the compact report to w. Columns:
//
//	TEMPLATE  PUBLISHED-ON  ENABLED  VULN  ENROLL  ESCs
//
// and a leading CA block with name, DNS, template count.
func (ShortFormatter) Format(w io.Writer, cas []*adcs.CertificateAuthority, templates []*adcs.Template) error {
	tty := isTerm(w)

	// CA summary table.
	caHeaders := []string{"CA", "DNS", "TEMPLATES"}
	caRows := make([][]string, 0, len(cas))
	for _, ca := range cas {
		if ca == nil {
			continue
		}
		caRows = append(caRows, []string{ca.Name, ca.DNSName, fmt.Sprintf("%d", len(ca.Templates))})
	}
	if err := printTable(w, caHeaders, caRows, tty); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w); err != nil {
		return err
	}

	// Template summary table.
	rows := make([]*adcs.Template, 0, len(templates))
	for _, t := range templates {
		if t != nil {
			rows = append(rows, t)
		}
	}
	sort.SliceStable(rows, func(i, j int) bool {
		return templateLabel(rows[i]) < templateLabel(rows[j])
	})

	tHeaders := []string{"TEMPLATE", "ENABLED", "VULN", "ENROLL", "ESCs", "PUBLISHED-ON"}
	tRows := make([][]string, 0, len(rows))
	for _, t := range rows {
		tRows = append(tRows, []string{
			templateLabel(t),
			boolCell(t.Enabled, tty),
			boolCell(len(t.Findings) > 0, tty),
			boolCell(t.EnrollableByCurrentUser, tty),
			escCell(t.Findings, tty),
			compactPublishedBy(t.PublishedBy),
		})
	}
	return printTable(w, tHeaders, tRows, tty)
}

// printTable emits a two-space-separated table with bold-cyan headers
// (when tty), computing column widths from the *visible* character count
// so ANSI-colored cells don't break alignment.
func printTable(w io.Writer, headers []string, rows [][]string, tty bool) error {
	widths := make([]int, len(headers))
	for i, h := range headers {
		widths[i] = ansiWidth(h)
	}
	for _, r := range rows {
		for i, cell := range r {
			if i >= len(widths) {
				break
			}
			if ww := ansiWidth(cell); ww > widths[i] {
				widths[i] = ww
			}
		}
	}

	writeRow := func(cells []string, asHeader bool) error {
		parts := make([]string, len(cells))
		for i, c := range cells {
			padded := padRight(c, widths[i])
			if asHeader {
				padded = header(padded, tty)
			}
			parts[i] = padded
		}
		_, err := fmt.Fprintln(w, strings.Join(parts, "  "))
		return err
	}

	if err := writeRow(headers, true); err != nil {
		return err
	}
	for _, r := range rows {
		if err := writeRow(r, false); err != nil {
			return err
		}
	}
	return nil
}

// compactPublishedBy keeps the PUBLISHED-ON column from ballooning when a
// template is published on every CA. Shows the first name verbatim and
// appends a "(+N more)" suffix for the rest. A template published on
// exactly one CA prints that CA name; an unpublished template prints "-".
func compactPublishedBy(pubs []string) string {
	if len(pubs) == 0 {
		return "-"
	}
	if len(pubs) == 1 {
		return pubs[0]
	}
	return fmt.Sprintf("%s (+%d more)", pubs[0], len(pubs)-1)
}

func templateLabel(t *adcs.Template) string {
	if t == nil {
		return ""
	}
	if t.DisplayName != "" {
		return t.DisplayName
	}
	return t.Name
}

func escKinds(findings []adcs.Finding) string {
	if len(findings) == 0 {
		return ""
	}
	seen := make(map[string]bool, len(findings))
	names := make([]string, 0, len(findings))
	for _, f := range findings {
		if seen[f.ESC] {
			continue
		}
		seen[f.ESC] = true
		names = append(names, f.ESC)
	}
	sort.Strings(names)
	return strings.Join(names, ",")
}

func yesNoShort(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}
