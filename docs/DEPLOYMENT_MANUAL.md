# Manual Debian deployment reference

Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
See [LICENSE](../LICENSE) for copyright ownership and licensing terms.

For the shorter, automated path, start with [DEPLOYMENT.md](../DEPLOYMENT.md).
This reference describes the individual steps for an operator-managed installation.
It uses PostgreSQL `18/main` on port 5432; the setup helper instead creates
`18/supivpn` on port 55433. Do not mix these database procedures.

This guide takes a fresh **Debian 13** server to a SAML-authenticated VPN using
the `supivpn` metapackage, `supivpn-node`, `supivpn-controller` and systemd.
PostgreSQL 18, the controller and the VPN node share one host. The agent talks
to the controller over a private Unix socket; no AWS account is needed.

**Evaluation status:** use a release containing Debian assets, or build locally
until the first such release is published. There is no SupiVPN APT repository.
The shipped VPN client template validates
the certificate chain, validity and server purpose, but does **not** verify the
server DNS name. Required DNS SAN verification in OpenVPN Connect remains
[unfinished](TLS_CRYPT_V2.md#planned-dns-san-verification). A successful
tunnel below does not close that production blocker or the other
[security review items](SECURITY_MODEL.md).

The first milestone is a working tunnel to the server. Private-network access
is a separate, explicit routing step. This is an IPv4 split tunnel: Internet
traffic and client DNS continue to use the client's normal connection.

Follow the sections in order: [host](#1-choose-names-and-prepare-the-host),
[packages](#2-obtain-and-install-the-packages),
[certificates](#3-prepare-certificates-and-the-wrapping-key),
[database](#4-install-postgresql-18-and-prepare-the-database),
[IdP](#5-register-the-saml-application),
[configuration](#6-configure-the-controller-and-node),
[firewall](#7-install-a-minimal-host-firewall),
[startup](#8-start-the-services-and-verify-readiness),
[client](#9-download-a-profile-and-connect), then optional
[private-network access](#10-add-access-to-a-private-network).

## 1. Choose names and prepare the host

You need administrator access to a SAML 2.0 IdP, two real DNS names you control,
a Debian host with `/dev/net/tun`, and an external client for the final test.
Use a dedicated host with no existing VPN, database or firewall configuration.
Keep a provider console available while changing its firewall.

| Example | Replace with |
| --- | --- |
| `vpn.example.test` | DNS-only A record pointing to the server's public IPv4; UDP 1194 must reach it |
| `login.example.test` | A record pointing to the same server; direct HTTPS on TCP 8443 |
| `198.51.100.10` | Your administrator's public IPv4 for SSH |
| `node-a` | Stable identity of this node; keep agent and controller values identical |
| `10.203.0.0/24` | An unused VPN subnet, distinct from client LANs and your private networks |
| `admins-vpn`, `engineers-production-vpn` | Exact IdP group names, also used in both JSON files |

The `.test` domains and documentation addresses cannot be used as real endpoints.
Do not proxy the VPN hostname through an HTTP CDN. This guide also uses direct
controller HTTPS; adding a proxy requires separate origin, cache and rate-limit
configuration. Do not publish AAAA records without configuring IPv6 reachability.

Unless a block says otherwise, run host commands in a **root Bash shell**:

```bash
sudo -i
umask 077
cat /etc/os-release
dpkg --print-architecture
systemctl --version
test -c /dev/net/tun
timedatectl status
apt-get update
apt-get upgrade
apt-get install ca-certificates curl openssl python3 nftables certbot iproute2 iputils-ping
```

Expect Debian 13, `amd64` or `arm64`, systemd 257 or newer, and synchronized time.
Correct time is necessary for TLS and SAML. Reboot first if OS updates require it.
Allow inbound SSH from your administration address, UDP 1194 and TCP 8443 in
the provider firewall. TCP 80 is also needed for the certificate procedure below.
Outbound DNS, time synchronization, HTTPS and APT access must work.

## 2. Obtain and install the packages

### OpenVPN

The current agent and package dependency require **OpenVPN Community 2.7.8**.
Broader version support is deferred; installing Debian's default OpenVPN without
checking its version is insufficient.

At the time of writing, Debian provides `2.7.8-1~bpo13+1` for both supported
architectures in [trixie-backports](https://packages.debian.org/trixie-backports/openvpn).
Add that signed repository following the
[Debian backports instructions](https://backports.debian.org/Instructions/):

```bash
cat > /etc/apt/sources.list.d/debian-backports.sources <<'EOF'
Types: deb
URIs: https://deb.debian.org/debian
Suites: trixie-backports
Components: main
Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg
EOF
chmod 0644 /etc/apt/sources.list.d/debian-backports.sources
apt-get update
apt-cache policy openvpn
apt-cache madison openvpn
apt-get --simulate install openvpn=2.7.8-1~bpo13+1
apt-get install openvpn=2.7.8-1~bpo13+1
/usr/sbin/openvpn --version
```

Expect `OpenVPN 2.7.8` on the first line. If this Debian revision is superseded,
review and select an available revision of upstream 2.7.8. Stop if none is
available; do not use testing/unstable packages, force dependencies, or install
the `ci/debian` OpenVPN test fixture on this server. Do not hold a vulnerable
version indefinitely: a future security update outside the accepted range
requires a corresponding SupiVPN compatibility update.

### SupiVPN

Prefer the ready-made packages from a GitHub Release containing `.deb` assets.
Follow [download and signature verification](../DEPLOYMENT.md#download-and-verify-supivpn),
then install the matching files on the VM. Releases v0.5.0 and earlier have no
Debian assets. Skip the workstation build below when using verified release
packages; use their version/architecture download directory in the install block.

For a local build fallback, on a **build workstation**, use a reviewed checkout
with Go from `go.mod`,
Python 3.11 or newer, Make and Docker available. Docker is build tooling only;
the deployed services run directly under systemd.

```bash
git clone https://github.com/SupiVPN/supivpn.git
cd supivpn
# Select and review the intended source commit before building.
git rev-parse HEAD
make setup
make deb-test ARCH=amd64
```

Use `ARCH=arm64` for an ARM64 server. The final build message names a new
`local/debian/<arch>/build-*` directory containing the three `.deb` files and
their matching vendored source, `.dsc`, `.changes` and `.buildinfo` files.
Keep this directory and the source commit as your installation record.
Optional `make deb-vm-test ARCH=amd64` adds real Debian VM acceptance before
installation; see [build prerequisites and evidence](DEBIAN_PACKAGING.md).

Transfer only the three intended `.deb` files over authenticated SSH into a new
directory on the server, such as `/root/supivpn-packages/`. Compare their SHA-256
hashes on both hosts (`sha256sum` on Linux, `shasum -a 256` on macOS).
This detects transfer errors; it does not turn unsigned local builds into signed
release artifacts. The Linux binary tarballs are not Debian packages; select
the `.deb` assets.

Back on the **Debian server**, with exactly one version of each package present:

```bash
cd /root/supivpn-packages
dpkg-deb --info ./supivpn-node_*.deb
dpkg-deb --info ./supivpn-controller_*.deb
dpkg-deb --info ./supivpn_*_all.deb
apt-get --simulate install ./supivpn-node_*.deb ./supivpn-controller_*.deb ./supivpn_*_all.deb
apt-get install ./supivpn-node_*.deb ./supivpn-controller_*.deb ./supivpn_*_all.deb
dpkg-query -W supivpn supivpn-node supivpn-controller openvpn
systemctl is-active supivpn-controller supivpn-node supivpn-openvpn
systemctl is-enabled supivpn-controller supivpn-node supivpn-openvpn
```

The SupiVPN packages must have matching versions and the correct architecture.
The last two commands are expected to return nonzero: services are initially
inactive and disabled/static. Installation does not create keys, configure a
VPN, run SQL migrations or start services. Use only the SupiVPN units; do not
also start an `openvpn-server@...` instance for this configuration.

## 3. Prepare certificates and the wrapping key

Obtain public HTTPS/server certificates. One Let's Encrypt certificate covering
both names works for this combined host. Replace the domains before running:

```bash
certbot certonly --standalone --cert-name supivpn \
  -d vpn.example.test -d login.example.test
install -d -o root -g root -m 0755 /etc/supivpn
install -d -o root -g root -m 0700 /etc/supivpn/node
install -d -o root -g supivpn-controller -m 0750 /etc/supivpn/controller
install -o root -g root -m 0600 /etc/letsencrypt/live/supivpn/cert.pem /etc/supivpn/node/crt.pem
install -o root -g root -m 0600 /etc/letsencrypt/live/supivpn/chain.pem /etc/supivpn/node/chain.pem
install -o root -g root -m 0600 /etc/letsencrypt/live/supivpn/privkey.pem /etc/supivpn/node/key.pem
install -o root -g supivpn-controller -m 0640 /etc/letsencrypt/live/supivpn/cert.pem /etc/supivpn/controller/crt.pem
install -o root -g supivpn-controller -m 0640 /etc/letsencrypt/live/supivpn/chain.pem /etc/supivpn/controller/chain.pem
install -o root -g supivpn-controller -m 0640 /etc/letsencrypt/live/supivpn/privkey.pem /etc/supivpn/controller/key.pem
openssl x509 -in /etc/supivpn/node/crt.pem -noout -dates -ext subjectAltName
```

[Certbot's standalone challenge](https://eff-certbot.readthedocs.io/en/stable/using.html#standalone)
needs both names to resolve correctly and TCP 80
to reach this host, with no other listener on that port. Other ACME/certificate
delivery systems are possible; retain the paths and permissions above. Never
make private keys world-readable to fix a service error.

Initialize the **server wrapping key once**, while its directory is private:

```bash
install -d -o root -g root -m 0700 /etc/supivpn/keys
/usr/sbin/supivpn-profile -init -server-key /etc/supivpn/keys/tls-crypt-v2-server.key
chown supivpn-controller:supivpn-controller /etc/supivpn/keys/tls-crypt-v2-server.key
chmod 0600 /etc/supivpn/keys/tls-crypt-v2-server.key
chown root:supivpn-controller /etc/supivpn/keys
chmod 0750 /etc/supivpn/keys
```

The root OpenVPN process and restricted controller now read the same key; the
controller's systemd sandbox cannot modify it. Securely back it up. Do not print
or rotate it during normal restarts: replacing it invalidates existing profiles.

## 4. Install PostgreSQL 18 and prepare the database

Use the [PostgreSQL project's signed APT repository](https://www.postgresql.org/download/linux/debian/):

```bash
install -d -m 0755 /usr/share/postgresql-common/pgdg
curl --fail --show-error --location \
  https://www.postgresql.org/media/keys/ACCC4CF8.asc \
  -o /usr/share/postgresql-common/pgdg/apt.postgresql.org.asc
chmod 0644 /usr/share/postgresql-common/pgdg/apt.postgresql.org.asc
cat > /etc/apt/sources.list.d/pgdg.sources <<'EOF'
Types: deb
URIs: https://apt.postgresql.org/pub/repos/apt
Suites: trixie-pgdg
Components: main
Signed-By: /usr/share/postgresql-common/pgdg/apt.postgresql.org.asc
EOF
chmod 0644 /etc/apt/sources.list.d/pgdg.sources
apt-get update
apt-get install postgresql-18
pg_lsclusters
```

Expect the `18/main` cluster on port 5432. The following configuration is for
this fresh, dedicated cluster; do not replace an existing database's access rules.
Keep it on loopback, with SCRAM passwords and verified TLS even though the
controller is on the same host.

Create a local self-signed database certificate whose public certificate is
explicitly trusted by this controller only. This is separate from the public
VPN/HTTPS certificates and does not change the client VPN trust model:

```bash
install -d -o postgres -g postgres -m 0700 /etc/postgresql/18/main/supivpn-tls
openssl req -x509 -newkey rsa:3072 -nodes -days 365 \
  -subj '/CN=localhost' -addext 'subjectAltName=DNS:localhost' \
  -addext 'extendedKeyUsage=serverAuth' \
  -keyout /etc/postgresql/18/main/supivpn-tls/server.key \
  -out /etc/postgresql/18/main/supivpn-tls/server.crt
chown postgres:postgres /etc/postgresql/18/main/supivpn-tls/server.key /etc/postgresql/18/main/supivpn-tls/server.crt
chmod 0600 /etc/postgresql/18/main/supivpn-tls/server.key /etc/postgresql/18/main/supivpn-tls/server.crt
install -o root -g supivpn-controller -m 0640 \
  /etc/postgresql/18/main/supivpn-tls/server.crt /etc/supivpn/controller/database-ca.pem
cat > /etc/postgresql/18/main/conf.d/supivpn.conf <<'EOF'
listen_addresses = '127.0.0.1'
ssl = on
ssl_cert_file = '/etc/postgresql/18/main/supivpn-tls/server.crt'
ssl_key_file = '/etc/postgresql/18/main/supivpn-tls/server.key'
password_encryption = 'scram-sha-256'
EOF
chmod 0644 /etc/postgresql/18/main/conf.d/supivpn.conf
cat > /etc/postgresql/18/main/pg_hba.conf <<'EOF'
local all postgres peer
hostssl supivpn supivpn_runtime,supivpn_migrator 127.0.0.1/32 scram-sha-256
EOF
chown postgres:postgres /etc/postgresql/18/main/pg_hba.conf
chmod 0640 /etc/postgresql/18/main/pg_hba.conf
systemctl restart postgresql@18-main
runuser -u postgres -- psql -X -c 'SHOW server_version;'
```

`pg_hba.conf` has no plaintext or remote fallback. PostgreSQL
[TLS file permissions](https://www.postgresql.org/docs/18/ssl-tcp.html) apply.
Track certificate expiry; replacing this self-signed certificate also requires
updating the controller trust file and restarting the controller.

Create separate owner, runtime and migration roles **before migrations**:

```bash
runuser -u postgres -- psql -X -v ON_ERROR_STOP=1 <<'SQL'
CREATE ROLE supivpn_owner NOLOGIN NOINHERIT;
CREATE ROLE supivpn_runtime LOGIN NOINHERIT;
CREATE ROLE supivpn_migrator LOGIN NOINHERIT;
GRANT supivpn_owner TO supivpn_migrator;
CREATE DATABASE supivpn;
REVOKE ALL ON DATABASE supivpn FROM PUBLIC;
GRANT CONNECT, CREATE ON DATABASE supivpn TO supivpn_owner;
GRANT CONNECT ON DATABASE supivpn TO supivpn_runtime, supivpn_migrator;
\connect supivpn
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT USAGE, CREATE ON SCHEMA public TO supivpn_owner;
CREATE SCHEMA supivpn AUTHORIZATION supivpn_owner;
GRANT USAGE ON SCHEMA supivpn TO supivpn_runtime;
ALTER DEFAULT PRIVILEGES FOR ROLE supivpn_owner IN SCHEMA supivpn
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO supivpn_runtime;
ALTER DEFAULT PRIVILEGES FOR ROLE supivpn_owner IN SCHEMA supivpn
  GRANT USAGE, SELECT ON SEQUENCES TO supivpn_runtime;
ALTER DEFAULT PRIVILEGES FOR ROLE supivpn_owner IN SCHEMA public
  GRANT SELECT ON TABLES TO supivpn_runtime;
SQL
runuser -u postgres -- psql -X
```

In the interactive `psql` session, set two different password-manager-generated
passwords using hidden prompts, then quit:

```text
\password supivpn_runtime
\password supivpn_migrator
\q
```

Use long random hexadecimal passwords to avoid quoting ambiguity in the example
connection strings. Never put real passwords in shell arguments, history or a
repository. The runtime has no owner membership, CREATE or TEMP privilege.

Run the installed migrator with its own identity. At the hidden prompt below,
enter this connection-string shape with the migration password substituted:

```text
host=localhost port=5432 dbname=supivpn user=supivpn_migrator password=REPLACE_WITH_MIGRATION_PASSWORD sslmode=verify-full sslrootcert=/etc/supivpn/controller/database-ca.pem
```

Keep `host=localhost` for the certificate's DNS name; ensure it resolves to
loopback, including `127.0.0.1`, on this host. Then run:

```bash
(
  read -r -s -p 'Migration connection string: ' SUPIVPN_DATABASE_URL
  printf '\n'
  export SUPIVPN_DATABASE_URL
  /usr/sbin/supivpn-migrate
)
```

Require exit status zero before continuing. Migrations are embedded in the
binary, transactionally applied as `supivpn_owner`, and currently reach schema 10.
Do not execute the inspection copies under `/usr/share/supivpn-controller/migrations`
individually. This is the non-AWS environment mode; `-config` is for the AWS
migration adapter, not the controller's JSON file.

Create the runtime environment file without exposing its contents in the terminal:

```bash
install -o root -g root -m 0600 /dev/null /etc/supivpn/controller/database.env
editor /etc/supivpn/controller/database.env
```

Its one line is the following, with the **runtime** password substituted:

```text
SUPIVPN_DATABASE_URL="host=127.0.0.1 port=5432 dbname=supivpn user=supivpn_runtime password=REPLACE_WITH_RUNTIME_PASSWORD"
```

systemd reads this root-only file before switching to the controller user.
The JSON below supplies authoritative TLS settings. Do not source this file in
a diagnostic shell or print it with `cat`/`systemctl show`.

## 5. Register the SAML application

Create a custom SAML 2.0 application in your IdP with these values, replacing
the hostname everywhere and preserving the port:

| Setting | Value |
| --- | --- |
| ACS / Single sign-on URL | `https://login.example.test:8443/saml/acs` |
| Recipient and Destination | Same ACS URL |
| Audience / SP Entity ID | `https://login.example.test:8443/saml/metadata` |
| NameID | Stable username; unspecified format |
| Response and assertion | Both signed, RSA-SHA256 / SHA256 |
| Assertion encryption | Off for this example |
| Signed AuthnRequests / Single Logout | Off for this example |
| Default RelayState | Empty |
| Group attribute | `groups`, unspecified or omitted NameFormat |

Each group must be a separate SAML `AttributeValue`, with exact case-sensitive
names. Assign the app and `admins-vpn` to a test user; prepare a second assigned
user with no allowed VPN group for the denial check. If a user has both configured
groups, priority 10 wins over 20; group permissions are not combined.

Download the IdP's public metadata XML through its trusted administrator interface
and transfer it to `/root/idp-metadata.xml` on the server. Inspect the intended
issuer and signing certificates, then install the same metadata for both services:

```bash
install -o root -g root -m 0600 /root/idp-metadata.xml /etc/supivpn/node/idp-metadata.xml
install -o root -g supivpn-controller -m 0640 /root/idp-metadata.xml /etc/supivpn/controller/idp-metadata.xml
```

The direct profile link below is sufficient; an IdP dashboard tile is optional.
For a tile, follow [profile launch settings](PROFILES.md#one-okta-saml-app).
Do not substitute `/saml/launch` for the actual authorization callback.

## 6. Configure the controller and node

Install the packaged examples as active files:

```bash
install -o root -g root -m 0600 /usr/share/doc/supivpn-node/examples/agent.example.json /etc/supivpn/node/agent.json
install -o root -g root -m 0600 /usr/share/doc/supivpn-node/examples/server.conf.example /etc/supivpn/node/openvpn.conf
install -o root -g supivpn-controller -m 0640 /usr/share/doc/supivpn-controller/examples/controller.example.json /etc/supivpn/controller/controller.json
install -o root -g supivpn-controller -m 0640 /usr/share/doc/supivpn-controller/examples/client.ovpn.example /etc/supivpn/controller/client.ovpn.template
id -u supivpn-controller
```

Edit `/etc/supivpn/controller/controller.json` to contain:

```json
{
  "logging": {"output": "stderr"},
  "public_url": "https://login.example.test:8443",
  "database_tls": {
    "mode": "verify-full",
    "ca_file": "/etc/supivpn/controller/database-ca.pem",
    "server_name": "localhost"
  },
  "idp_metadata": "/etc/supivpn/controller/idp-metadata.xml",
  "saml_groups_attribute": "groups",
  "groups": [
    {"name": "admins-vpn", "priority": 10, "max_connections_per_user": 2},
    {"name": "engineers-production-vpn", "priority": 20, "session_seconds": 3600}
  ],
  "pending_seconds": 180,
  "session_seconds": 43200,
  "max_connections_per_user": 1,
  "profile": {
    "endpoint": "vpn.example.test",
    "template_file": "/etc/supivpn/controller/client.ovpn.template",
    "server_key_file": "/etc/supivpn/keys/tls-crypt-v2-server.key"
  },
  "vm": {
    "listen": ":8443",
    "tls_certificate": "/etc/supivpn/controller/crt.pem",
    "tls_chain": "/etc/supivpn/controller/chain.pem",
    "tls_private_key": "/etc/supivpn/controller/key.pem",
    "agent_socket": "/run/supivpn-controller/agent.sock",
    "agent_uid": 0,
    "node_id": "node-a"
  }
}
```

Edit `/etc/supivpn/node/agent.json` to contain:

```json
{
  "logging": {"output": "stderr"},
  "public_url": "https://vpn.example.test:9443",
  "listen": "127.0.0.1:9443",
  "tls_certificate": "/etc/supivpn/node/crt.pem",
  "tls_chain": "/etc/supivpn/node/chain.pem",
  "tls_private_key": "/etc/supivpn/node/key.pem",
  "idp_metadata": "/etc/supivpn/node/idp-metadata.xml",
  "management_socket": "/run/supivpn/management.sock",
  "pending_seconds": 180,
  "session_seconds": 43200,
  "max_connections_per_user": 1,
  "saml_groups_attribute": "groups",
  "vpn_network": "10.203.0.0/24",
  "group_pools": [
    {"group_name": "admins-vpn", "priority": 10, "max_connections_per_user": 2, "cidr": "10.203.0.0/26"},
    {"group_name": "engineers-production-vpn", "priority": 20, "session_seconds": 3600, "cidr": "10.203.0.64/26"}
  ],
  "remote_controller": {
    "transport": "unix",
    "agent_socket": "/run/supivpn-controller/agent.sock",
    "controller_uid": 0,
    "public_url": "https://login.example.test:8443",
    "node_id": "node-a",
    "state_directory": "/var/lib/supivpn-node"
  }
}
```

**Replace `remote_controller.controller_uid: 0` with the numeric output of
`id -u supivpn-controller`.** The controller's `vm.agent_uid: 0` stays zero:
the packaged node agent runs as root with restricted capabilities. These checks
authenticate the Unix peer; do not change socket permissions to bypass them.
All names, URLs, group priorities and policy limits must agree between files.

The packaged OpenVPN file already supplies `server 10.203.0.0 255.255.255.0 nopool`,
`dev supivpn0`, UDP 1194, the matching management socket, `learn-address`, and
the certificate/key paths above. Keep its management and authentication options.
Do not add another address pool, client certificates, `client-to-client`, or
`redirect-gateway` to this baseline. If changing the VPN subnet, change the
server network, agent pools and firewall together.

The profile template contains a public ISRG Root X1 CA and a key placeholder.
The controller replaces its remote hostname and fills the key when issuing a
profile. It is **not** an importable profile itself. Verify that your server
chain reaches this CA before starting; do not disable verification on failure:

```bash
sed -n '/^<ca>$/,/^<\/ca>$/p' /etc/supivpn/controller/client.ovpn.template \
  | sed '1d;$d' > /run/supivpn-profile-ca.pem
openssl verify -purpose sslserver -CAfile /run/supivpn-profile-ca.pem \
  -untrusted /etc/supivpn/node/chain.pem /etc/supivpn/node/crt.pem
/usr/sbin/supivpn -config /etc/supivpn/node/agent.json -check-config
systemd-analyze verify supivpn-controller.service supivpn-node.service supivpn-openvpn.service
```

These checks do not fix or test the missing VPN client DNS SAN verification.
Do not silently replace that planned behavior with CN matching or fingerprint
pinning. The controller has no `-check-config` flag; its startup and health check
in step 8 validate its configuration and database connection.

## 7. Install a minimal host firewall

This baseline permits only administration, public login, OpenVPN and a ping to
the VPN gateway. No VPN client can reach other host services, other clients,
metadata endpoints or forwarded networks. There is no NAT or forwarding yet.

On this **fresh dedicated host only**, put the following in `/etc/nftables.conf`.
Replace `198.51.100.10` and the SSH port if necessary. `flush ruleset` replaces
all existing rules; do not apply this file on a host with another firewall manager.

```nft
#!/usr/sbin/nft -f
flush ruleset
table inet supivpn {
  chain input {
    type filter hook input priority 0; policy drop;
    iifname "lo" accept
    ct state invalid drop
    iifname "supivpn0" ip saddr { 10.203.0.0/26, 10.203.0.64/26 } ip daddr 10.203.0.1 icmp type echo-request accept
    iifname "supivpn0" drop
    ct state established,related accept
    ip saddr 198.51.100.10 tcp dport 22 accept
    tcp dport { 80, 8443 } accept
    udp dport 1194 accept
    ip protocol icmp accept
    meta l4proto ipv6-icmp accept
    udp sport 67 udp dport 68 accept
    udp sport 547 udp dport 546 accept
  }
  chain forward {
    type filter hook forward priority 0; policy drop;
  }
  chain output {
    type filter hook output priority 0; policy accept;
  }
}
```

Review the rules from the provider console and retain your current SSH session:

```bash
nft --check --file /etc/nftables.conf
nft --file /etc/nftables.conf
systemctl enable nftables
nft list ruleset
```

Verify a **new** SSH connection before closing the old one. Port 80 serves only
ACME renewal challenges; 9443 and 5432 stay local. Use provider/network controls
for connection-rate limits appropriate to your public endpoint.

## 8. Start the services and verify readiness

Start the controller first:

```bash
systemctl start supivpn-controller
curl --fail --show-error --noproxy '*' \
  --resolve login.example.test:8443:127.0.0.1 \
  https://login.example.test:8443/healthz
```

Require HTTP 200 with normal certificate verification. This checks database/schema
readiness, not the VPN tunnel. If it fails, stop here and use the diagnostics below.

```bash
systemctl start supivpn-node
systemctl is-active supivpn-controller supivpn-node supivpn-openvpn
curl --fail --show-error --noproxy '*' \
  --resolve vpn.example.test:9443:127.0.0.1 \
  https://vpn.example.test:9443/readyz
ss -lntup
stat -c '%a %U:%G %n' /run/supivpn /run/supivpn-controller \
  /run/supivpn/management.sock /run/supivpn-controller/agent.sock
ip -4 address show dev supivpn0
```

Allow initial node startup time, then require all three units active, `/readyz`
HTTP 200, `10.203.0.1/24` on `supivpn0`, UDP 1194, public TCP 8443, and loopback
9443/5432. Runtime directories are 0700 and sockets 0600. The node's systemd
notification only means listeners are ready; the HTTPS check additionally covers
OpenVPN/management and lease readiness.

## 9. Download a profile and connect

On an external computer, use a current OpenVPN Connect release supporting the
SAML browser flow (`IV_SSO=webauth`) and `tls-crypt-v2`. A generally supported
minimum client version has not yet been established; record the exact client
version and OS you test. The automated VM suite uses a Community 2.7.8 test
client and synthetic SAML; it does not prove your Connect UI or real IdP works.

1. Open `https://login.example.test:8443/profile` in the browser. Check that the
   HTTPS certificate is trusted and the redirect reaches your intended IdP.
2. Sign in as the user assigned to `admins-vpn`. Download `supivpn.ovpn` and
   import it into OpenVPN Connect. Treat the file as sensitive key material.
3. Connect. Complete the new browser SAML flow requested by the VPN client.
   A profile download alone does not authorize a VPN session.
4. Confirm the client received an address from `10.203.0.0/26` and run
   `ping 10.203.0.1` from the client. Check the node journal for the selected
   group and assigned IP. Internet/DNS should still use the normal connection.
5. Disconnect and reconnect: the next connection must obtain fresh SAML
   authorization, although an existing IdP session can avoid a password prompt.
6. Test the assigned user with no allowed VPN group: profile issuance must be
   denied, and an existing profile must not let that user establish a tunnel.
   An unassigned user must be rejected by the IdP.
7. Verify both groups independently, the lower-numbered priority for a user in
   both groups, and that disallowed host/forwarded services remain unreachable.

After these checks pass, enable startup across reboots:

```bash
systemctl enable supivpn-controller supivpn-node
systemctl is-enabled supivpn-controller supivpn-node
```

Do not independently enable `supivpn-openvpn`. It follows `supivpn-node`.
Schedule one reboot with console access, repeat step 8, and establish another
client tunnel before considering startup acceptance complete.

## 10. Add access to a private network

Skip this section if the gateway ping is all you need for the initial evaluation.
For a concrete routed example, suppose the server has a private interface `ens4`
at `10.50.0.10/24`, and a test application is at `10.50.0.20`. Replace these
addresses and interface names with your actual, non-overlapping network.

1. Ensure the VPN host can reach the application itself. Add a return route on
   the private network's router: `10.203.0.0/24 via 10.50.0.10`. If testing one
   Linux application host without router access, add that route on that host:
   `ip route add 10.203.0.0/24 via 10.50.0.10`, then persist it through that
   host's network manager. This is a command for the **application host**, not
   the VPN host. Its own firewall must allow the intended group source CIDRs.
2. Add this line to `/etc/supivpn/node/openvpn.conf`:

   ```text
   push "route 10.50.0.0 255.255.255.0"
   ```

3. Replace the empty `forward` chain in `/etc/nftables.conf` with the following.
   Administrators get SSH/HTTPS, engineers get HTTPS only. All other forwarding,
   including VPN-to-VPN and metadata traffic, remains denied:

   ```nft
   chain forward {
     type filter hook forward priority 0; policy drop;
     ct state invalid drop
     iifname "supivpn0" ip saddr != { 10.203.0.0/26, 10.203.0.64/26 } drop
     iifname "supivpn0" ip daddr 169.254.0.0/16 drop
     iifname "supivpn0" oifname "supivpn0" drop
     iifname "supivpn0" oifname "ens4" ip saddr 10.203.0.0/26 ip daddr 10.50.0.20 tcp dport { 22, 443 } accept
     iifname "supivpn0" oifname "ens4" ip saddr 10.203.0.64/26 ip daddr 10.50.0.20 tcp dport 443 accept
     iifname "ens4" oifname "supivpn0" ip saddr 10.50.0.20 ip daddr { 10.203.0.0/26, 10.203.0.64/26 } ct state established,related accept
   }
   ```

4. Check/apply the firewall before enabling forwarding on the **VPN host**:

   ```bash
   nft --check --file /etc/nftables.conf
   nft --file /etc/nftables.conf
   printf 'net.ipv4.ip_forward=1\n' > /etc/sysctl.d/90-supivpn.conf
   sysctl -p /etc/sysctl.d/90-supivpn.conf
   systemctl restart supivpn-node
   ```

   Restarting the pair disconnects existing tunnels. Reconnect and test an actual
   allowed TCP service, for example HTTPS using its trusted application hostname
   mapped to `10.50.0.20`. Check the return route and counters with
   `nft list chain inet supivpn forward`. Test that engineers cannot use SSH.

There is deliberately **no masquerade**: the destination sees the group-assigned
source IP. Broad SNAT would remove that distinction. Cloud networks may also
require routing/source-destination-check changes; a local sysctl cannot replace
those controls. Do not open all forwarding to diagnose a missing return route.

Private DNS is optional and separate. Start with IP reachability; configure a
restricted resolver and client DNS only after choosing your private domains.
Do not shadow the public controller name. Full tunnel, Internet SNAT, DNS-leak
protection and IPv6 bypass prevention need their own design and client tests;
see [routing and DNS](HOST.md#routing-and-isolation). This guide does not
claim to route or protect all of the client's Internet traffic.

## Operations and troubleshooting

Use `supivpn-node` to control the agent/OpenVPN pair:

```bash
systemctl stop supivpn-node
systemctl start supivpn-node
journalctl -u supivpn-controller -u supivpn-node -u supivpn-openvpn --since '10 minutes ago' --no-pager
```

Stopping only `supivpn-openvpn` while the node is active lets systemd start it
again. Both services use failure recovery with a five-starts-per-120-seconds
limit. Correct the underlying failure before `systemctl reset-failed`; do not
put reset commands in a retry loop. Controller/database loss eventually closes
tunnels when authorization leases expire; restoration requires fresh admission.

| Symptom | Check |
| --- | --- |
| APT cannot satisfy `openvpn` | Architecture and available 2.7.8 Debian revision; never force dependencies |
| Controller cannot start | JSON syntax, file ownership, environment file, IdP metadata and certificate paths |
| Controller `/healthz` is not 200 | PostgreSQL service, verified TLS name/CA, runtime password, grants and successful migrations |
| Node peer authentication fails | Actual `supivpn-controller` UID, `agent_uid: 0`, matching node ID and socket paths |
| Node active but `/readyz` fails | OpenVPN unit/journal, TUN device, management socket, matching subnet and controller readiness |
| TLS/profile import fails | Leaf/intermediate chain, template CA, certificate validity and client version; do not disable checks |
| SAML callback is rejected | Exact ACS/entity ID including port, signatures, clock, metadata, browser cookie and groups claim |
| Tunnel works but private service does not | Route push, forwarding, return route, destination firewall and group source IP |
| Repeated starts are refused | Fix the error first, then clear only the affected units' failed/start-limit state |

Do not collect full SAML assertions, cookies, login URLs with tickets, database
connection strings or `.ovpn` contents in support logs. Journal entries can contain
verified usernames and network addresses; apply suitable access and retention.

**Renewal:** the certificate files above are copies. Certbot renewal alone does
not update the running services. Reinstall the renewed leaf/chain/key with the
same owners and modes, verify the chain, then restart the controller and node
in a maintenance window and repeat readiness/login checks. Node restart drops
tunnels. Validate the ACME renewal path in advance; coordinate database
certificate/trust renewal separately.

**Upgrades:** retain the package/source record, configuration and secure key/DB
backups. Review schema compatibility and install matching component versions.
Packages preserve existing configuration, enablement and running processes;
installation does not automatically run migrations or restart them. Follow the
release's migration order, then explicitly restart and verify both services.
An incompatible downgrade or old database snapshot can revive stale authorization
state; follow [database upgrade guidance](POSTGRES.md#reconnect-and-migrations)
and [recovery](RECOVERY.md). Never delete `/var/lib/supivpn-node` as a repair.

**Removal:** removing the metapackage alone does not directly remove its two
components, but APT autoremove may do so unless they are marked manual.
Component removal stops its services. Purge deliberately retains operator
configuration, keys, persistent generation state and the controller account.
PostgreSQL data is separate. Review and back up these resources before any
explicit decommissioning cleanup.

## What has been verified

The [Debian VM suite](DEBIAN_PACKAGING.md#disposable-vm-checks) has passed
on amd64 and arm64 with real systemd, restricted database roles and verified TLS,
signed synthetic SAML, profile issuance, actual tunnel traffic, process crashes,
controller/database outages, session expiry/reconnect, reboot and package upgrades.
It uses an isolated OpenVPN build and synthetic certificates/IdP.

The commands here are an operator procedure assembled from those tested paths.
Public ACME issuance, the Debian backports package, your actual IdP/Connect client,
provider firewall and private-network routing require the checks above in your
environment; they are not covered by that VM result. Signed `.deb` distribution,
multi-host deployment, Lambda/IaC and container deployment are outside this guide.
