# Certigo

Pure-Go 1:1 port of [Certipy](https://github.com/ly4k/Certipy) (`certipy-ad` v5.0.3). Active Directory Certificate Services enumeration and abuse in a single static binary.

> **Status:** pre-alpha scaffold (v0.0.1). No subcommands implemented yet. See [design spec](docs/superpowers/specs/2026-04-19-certigo-design.md) and [milestone plan](docs/superpowers/plans/) for roadmap.

## Install

### From source

```bash
go install github.com/ajm4n/certigo/cmd/certigo@latest
```

### Binaries

Download from [Releases](https://github.com/ajm4n/certigo/releases). Supports `linux/{amd64,arm64}`, `windows/{amd64,arm64}`, `darwin/{amd64,arm64}`.

## Feature matrix

| Subcommand | Status | Milestone |
|---|---|---|
| `find`     | stub | M2 |
| `auth`     | stub | M3 |
| `cert`     | stub | M3 |
| `shadow`   | stub | M3 |
| `req`      | stub | M4 |
| `forge`    | stub | M4 |
| `ca`       | stub | M5 |
| `template` | stub | M5 |
| `account`  | stub | M5 |
| `ptt`      | stub | M6 |
| `parse`    | stub | M6 |
| `relay`    | stub | M7 |

## License

MIT. See [LICENSE](LICENSE).

## Acknowledgements

Certigo is a direct port of [Oliver Lyak's Certipy](https://github.com/ly4k/Certipy). All original research credit belongs to the Certipy authors.
