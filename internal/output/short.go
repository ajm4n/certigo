package output

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/ajm4n/certigo/internal/adcs"
)

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
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)

	if _, err := fmt.Fprintln(tw, "CA\tDNS\tTEMPLATES"); err != nil {
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
	if _, err := fmt.Fprintln(tw, "TEMPLATE\tPUBLISHED-ON\tENABLED\tVULN\tENROLL\tESCs"); err != nil {
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
		pub := "-"
		if len(t.PublishedBy) > 0 {
			pub = strings.Join(t.PublishedBy, ",")
		}
		escs := escKinds(t.Findings)
		escCol := "-"
		if escs != "" {
			escCol = escs
		}
		if _, err := fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n",
			name,
			pub,
			yesNoShort(t.Enabled),
			yesNoShort(len(t.Findings) > 0),
			yesNoShort(t.EnrollableByCurrentUser),
			escCol,
		); err != nil {
			return err
		}
	}
	return tw.Flush()
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
