# Certigo Local Docker Lab

## Overview

This lab is a one-command, reproducible Active Directory environment that
contributors can spin up on their workstation to test Certigo's
LDAP, Kerberos, NTLM, and AD CS request plumbing. It runs a real
[Samba AD DC](https://wiki.samba.org/index.php/Setting_up_Samba_as_an_Active_Directory_Domain_Controller)
so LDAP, Kerberos, DNS, and SMB behave like a production domain controller.

Real AD CS (Active Directory Certificate Services) only runs on Windows and
cannot be containerized. To keep the dev loop fast, this lab includes a small
Go HTTP stub (`mock-adcs`) that answers a handful of AD CS URLs
(`/certsrv/`, `/certsrv/certrqma.asp`, etc.) with HTTP auth challenges and
`501 Not Implemented` bodies. That is enough to exercise Certigo's transport,
auth negotiation, and error paths. Release-gate testing against a real AD CS
instance is done in the Tier 3 Windows VM lab under `lab/vm/` (future work).

## Prerequisites

- Docker 24+
- Docker Compose v2 (`docker compose`, not the legacy `docker-compose`)

## Quickstart

```bash
cd lab/docker
docker compose up -d
docker compose logs -f samba-ad-dc   # watch Samba provisioning (~60s first run)
```

When the Samba healthcheck reports `healthy`, the lab is ready.

## Using the Lab

### LDAP bind against Samba AD DC

```bash
ldapsearch -x -H ldap://localhost:389 \
  -D "CN=Administrator,CN=Users,DC=ctg,DC=local" \
  -w 'Str0ngP@ssw0rd!' \
  -b "DC=ctg,DC=local" \
  "(objectClass=user)"
```

Realm: `CTG.LOCAL`  NetBIOS domain: `CTG`  Admin password: `Str0ngP@ssw0rd!`

### Mock AD CS

```bash
curl -v http://localhost:8080/health
curl -v http://localhost:8080/certsrv/                 # expect 401 + WWW-Authenticate
curl -v http://localhost:8080/certsrv/certrqma.asp     # expect 501
curl -vk https://localhost:8443/health                 # HTTPS with self-signed cert
```

## Teardown

```bash
docker compose down       # stop containers, keep the samba-data volume
docker compose down -v    # stop and purge volumes (clean slate)
```

## FAQ

**Why isn't real AD CS available in this lab?**
Because AD CS doesn't run on Linux. We use real Samba for LDAP and Kerberos
and mocks for AD CS. Release-gate testing uses the Tier 3 Windows VM lab
under `lab/vm/` (future).
