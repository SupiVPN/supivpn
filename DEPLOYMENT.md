# Deploy SupiVPN on Debian

Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
See [LICENSE](LICENSE) for copyright ownership and licensing terms.

One Debian 13 VM, three `.deb` packages, one setup file. The `supivpn` package
installs both components and provides `supivpn-setup` to configure the controller,
node and local PostgreSQL 18 database. Services run directly under systemd.

**Evaluation status:** the shipped VPN client template verifies the certificate
chain but does not yet enforce the server DNS name.
[DNS SAN verification](docs/TLS_CRYPT_V2.md#planned-dns-san-verification)
remains a production blocker. The helper does not remove that limitation.

The short path below establishes a split tunnel and a ping to the VPN gateway.
Private-network access is an explicit follow-up. Client Internet traffic and DNS
continue through the client's normal connection.

## 1. Prepare the VM and packages

Use a fresh, dedicated **Debian 13 amd64 or arm64** VM with systemd 257+,
`/dev/net/tun`, synchronized time and provider console access. You need:

- One real DNS hostname, such as `vpn.example.test`, pointing directly to the VM.
  Replace this example everywhere. Do not put the hostname behind an HTTP CDN.
- Administrator access to a SAML 2.0 IdP and the exact allowed group names.
- Your SSH source IPv4/CIDR. The example `198.51.100.10/32` must be replaced.
- Provider firewall access: SSH from that source, TCP 80 for ACME,
  TCP 8443 for login/profile download and UDP 1194 for OpenVPN.
  Do not expose the database or node health port. Do not publish an AAAA record
  without configuring IPv6 reachability.

The APT path needs no Go SDK, Docker, source checkout or GitHub account on the VM.
**Publication status:** `apt.supivpn.com` must be enabled and populated by the
first stable package release before these commands work. v0.5.0 and earlier
have no `.deb` assets. Until that launch, use the
[local build fallback](docs/DEBIAN_PACKAGING.md#build-and-check).

On the VM, enter a root Bash shell and install the prerequisites:

```bash
sudo -i
umask 077
apt-get update
apt-get upgrade
apt-get install ca-certificates curl gnupg openssl python3 nftables certbot iproute2 iputils-ping
test -c /dev/net/tun
timedatectl status
```

### Add the SupiVPN repository

Run in Bash. The source pins the release certificate as well as its key file;
APT then verifies the signed index and each package automatically. Do not use
`apt-key`, `trusted=yes` or an unauthenticated installation override.

```bash
set -euo pipefail
install -d -m 0755 /etc/apt/keyrings
curl --fail --show-error --location --proto '=https' --proto-redir '=https' \
  https://apt.supivpn.com/supivpn.asc -o /etc/apt/keyrings/supivpn.asc
cat > /etc/apt/sources.list.d/supivpn.sources <<'EOF'
Types: deb
URIs: https://apt.supivpn.com
Suites: trixie
Components: main
Architectures: amd64 arm64
Signed-By: /etc/apt/keyrings/supivpn.asc A43155B36661034A4FA89E373681E6DFB83B35E2
EOF
chmod 0644 /etc/apt/keyrings/supivpn.asc /etc/apt/sources.list.d/supivpn.sources
```

The fingerprint is pinned in the [release-key policy](DEVELOPERS.md#release-signing).
The published public certificate contains only its artifact-signing subkey.
For offline installation or prereleases, use the
[GitHub Release download instructions](docs/RELEASES.md#download-and-verify-supivpn).

### Install dependencies and packages

Enable the signed [Debian backports](https://backports.debian.org/Instructions/)
and [PostgreSQL APT](https://www.postgresql.org/download/linux/debian/)
repositories once:

```bash
cat > /etc/apt/sources.list.d/debian-backports.sources <<'EOF'
Types: deb
URIs: https://deb.debian.org/debian
Suites: trixie-backports
Components: main
Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg
EOF
install -d -m 0755 /usr/share/postgresql-common/pgdg
curl --fail --show-error --location --proto '=https' --proto-redir '=https' \
  https://www.postgresql.org/media/keys/ACCC4CF8.asc \
  -o /usr/share/postgresql-common/pgdg/apt.postgresql.org.asc
cat > /etc/apt/sources.list.d/pgdg.sources <<'EOF'
Types: deb
URIs: https://apt.postgresql.org/pub/repos/apt
Suites: trixie-pgdg
Components: main
Signed-By: /usr/share/postgresql-common/pgdg/apt.postgresql.org.asc
EOF
chmod 0644 /etc/apt/sources.list.d/debian-backports.sources \
  /etc/apt/sources.list.d/pgdg.sources \
  /usr/share/postgresql-common/pgdg/apt.postgresql.org.asc
apt-get update
apt-cache madison openvpn
apt-get install postgresql-18 openvpn=2.7.8-1~bpo13+1
apt-cache policy supivpn supivpn-node supivpn-controller
apt-get install supivpn
```

The current agent requires upstream OpenVPN **2.7.8**. If the Debian revision above is superseded,
select the available revision of that same upstream version after review;
never force dependencies or install the CI test fixture. See the
[manual package section](docs/DEPLOYMENT_MANUAL.md#2-obtain-and-install-the-packages)
for details. SupiVPN package installation leaves its services stopped.

## 2. Supply the hostname, certificate and IdP

Obtain a certificate covering the hostname; Certbot needs direct TCP 80 access:

```bash
certbot certonly --standalone --cert-name supivpn -d vpn.example.test
```

Create a SAML application in your IdP:

| Setting | Value |
| --- | --- |
| ACS / Recipient / Destination | `https://vpn.example.test:8443/saml/acs` |
| Audience / Entity ID | `https://vpn.example.test:8443/saml/metadata` |
| NameID | Stable username; unspecified format |
| Response and assertion signatures | Both signed; RSA-SHA256 / SHA256 |
| Group attribute | `groups`; one `AttributeValue` per group |
| Encryption, signed AuthnRequests, Single Logout | Off for this baseline |
| Default RelayState | Empty |

Assign an allowed test user and download the IdP's public metadata through its
trusted administrator interface to `/root/idp-metadata.xml`. Prepare a second
assigned user with no allowed VPN group for the denial test.

Copy and edit **one** small setup file:

```bash
install -m 0600 /usr/share/supivpn/examples/setup.example.json /root/supivpn-setup.json
editor /root/supivpn-setup.json
```

```json
{
  "hostname": "vpn.example.test",
  "certificate_directory": "/etc/letsencrypt/live/supivpn",
  "idp_metadata_file": "/root/idp-metadata.xml",
  "groups": ["admins-vpn", "engineers-production-vpn"],
  "admin_cidr": "198.51.100.10/32"
}
```

Group names are case-sensitive; the first matching group wins. The default VPN
network is `10.203.0.0/24`, divided into equal group pools. It must not overlap
client LANs or destination networks. Optional fields: `vpn_network`, `ssh_port`
(default 22), `login_hostname` (defaults to `hostname`), and `database_name`
(default `supivpn`). A separate login hostname needs DNS and certificate coverage.
Do not put passwords or private-key contents in this file.

## 3. Run setup

```bash
supivpn-setup plan --config /root/supivpn-setup.json
supivpn-setup init --config /root/supivpn-setup.json
```

`plan` displays the intended changes and the exact SAML URLs without modifying
the host. `init` validates the certificate, chain, hostname and key pair; generates
consistent controller/agent/OpenVPN configuration with the actual service UID;
installs metadata and certificate copies with restricted permissions; and creates
the wrapping key once.

It also creates a **dedicated PostgreSQL cluster `18/supivpn`**, listening only
on `127.0.0.1:55433`, with verified TLS, separate owner/runtime/migration roles,
random credentials and applied migrations. Existing PostgreSQL clusters are
untouched. Credentials stay in root-only files under `/etc/supivpn/controller/`;
do not print them. The generated database certificate expires after one year.

Setup starts only its new database. It does not apply firewall rules, start the
VPN or enable services at boot. Existing SupiVPN configuration, keys, node state
or its database cluster cause a refusal. After a partial failure, inspect the
reported step locally using the [manual reference](docs/DEPLOYMENT_MANUAL.md);
do not delete state or rerun setup blindly. `init` is not an upgrade command.

## 4. Review the firewall, start and check

The generated firewall allows SSH from `admin_cidr`, public login/OpenVPN, and
only a gateway ping from VPN clients. Forwarding is denied. Applying it replaces
the existing ruleset, so use this only on the fresh dedicated VM, from a provider
console with your current SSH session retained:

```bash
editor /etc/supivpn/firewall.nft
nft --check --file /etc/supivpn/firewall.nft
install -m 0600 /etc/supivpn/firewall.nft /etc/nftables.conf
nft --file /etc/nftables.conf
systemctl enable nftables
systemctl start supivpn-controller
systemctl start supivpn-node
supivpn-setup check
```

Verify a **new SSH connection** before closing the old one. All four services
must be active; controller `/healthz` and node `/readyz` must pass with TLS
verification. If the node is still starting, wait a few seconds and run `check`
again. The OpenVPN service follows the node; do not start or enable it separately.

## 5. Connect and finish acceptance

1. Open `https://vpn.example.test:8443/profile`, sign in through the intended IdP,
   download the profile and import it into a current OpenVPN Connect client.
   The profile contains key material; do not share or log it.
2. Connect and complete the VPN's browser login. Confirm an address from the
   assigned group pool, then `ping 10.203.0.1` (or your selected gateway).
3. Reconnect and confirm fresh SAML authorization. Verify the user without an
   allowed group is denied, and disallowed host/private services stay unreachable.
4. Record the client version/OS. A general minimum Connect version is not yet
   established; the automated VM tests use a Community client and synthetic IdP.

After acceptance, enable the dedicated database and SupiVPN at boot:

```bash
systemctl enable postgresql@18-supivpn supivpn-controller supivpn-node
```

Schedule a reboot with console access, then repeat `supivpn-setup check` and a
client connection. For useful private application access, follow the
[routed-network example](docs/DEPLOYMENT_MANUAL.md#10-add-access-to-a-private-network):
add route pushes, forwarding rules for specific group pools and a return route.
The helper uses equal group pools; get their exact CIDRs from `agent.json`, rather
than copying the manual example's CIDRs. It deliberately adds no full-tunnel NAT.

## Maintenance and troubleshooting

```bash
supivpn-setup check
systemctl status postgresql@18-supivpn supivpn-controller supivpn-node supivpn-openvpn --no-pager
journalctl -u supivpn-controller -u supivpn-node -u supivpn-openvpn -n 100 --no-pager
```

Do not post credentials, profiles, cookies or complete SAML assertions in support
logs. For symptoms and recovery, see the
[manual diagnostics](docs/DEPLOYMENT_MANUAL.md#operations-and-troubleshooting).
Use PostgreSQL unit `postgresql@18-supivpn` and port **55433** for helper installs;
the manual procedure uses `18/main:5432` instead.

**Certificate renewal:** Certbot maintains its source directory, while services
use restricted copies. After a successful renewal, in a maintenance window:

```bash
systemctl stop supivpn-node supivpn-controller
supivpn-setup certificates
systemctl start supivpn-controller supivpn-node
supivpn-setup check
```

This disconnects clients. The command validates the renewed chain and hostnames
before replacing any service copies; it does not change the wrapping key or DB
certificate. Track DB certificate expiry separately and update its trust copy as
described in the manual database section, using the helper's cluster paths.

**Upgrades:** keep encrypted backups of the database, configuration, wrapping key
and node generation state. Install matching packages, follow the release's schema
upgrade order, and restart explicitly. The root-only `migration.env` contains the
separate migration identity for `supivpn-migrate`; do not reuse runtime credentials
or run `init` again. See [database migrations](docs/POSTGRES.md#reconnect-and-migrations).

The package/VM suite checks setup with synthetic certificates and IdP, real
systemd, restricted database roles, tunnel traffic, recovery and reboot. Public
ACME issuance, Debian backports, provider networking and your real IdP/Connect
client still require the acceptance above. [Packaging details](docs/DEBIAN_PACKAGING.md)
cover local builds and release delivery.
