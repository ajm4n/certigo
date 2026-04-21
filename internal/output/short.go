package output

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/ajm4n/certigo/internal/adcs"
)

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
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)

	if _, err := fmt.Fprintln(tw, header("CA\tDNS\tTEMPLATES", tty)); err != nil {
		return err
	}
	for _, ca := range cas {
		if ca == nil {
			continue
		}
		if _, err := fmt.Fprintf(tw, "%s\t%s\t%d\n", ca.Name, ca.DNSName, len(ca.Templates)); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintln(tw, ""); err != nil {
		return err
	}
	if err := tw.Flush(); err != nil {
		return err
	}

	tw = tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	if _, err := fmt.Fprintln(tw, header("TEMPLATE\tENABLED\tVULN\tENROLL\tESCs\tPUBLISHED-ON", tty)); err != nil {
		return err
	}

	rows := make([]*adcs.Template, 0, len(templates))
	for _, t := range templates {
		if t != nil {
			rows = append(rows, t)
		}
	}
	sort.SliceStable(rows, func(i, j int) bool {
		return templateLabel(rows[i]) < templateLabel(rows[j])
	})

	for _, t := range rows {
		name := templateLabel(t)
		if _, err := fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n",
			name,
			boolCell(t.Enabled, tty),
			boolCell(len(t.Findings) > 0, tty),
			boolCell(t.EnrollableByCurrentUser, tty),
			escCell(t.Findings, tty),
			compactPublishedBy(t.PublishedBy),
		); err != nil {
			return err
		}
	}
	return tw.Flush()
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
