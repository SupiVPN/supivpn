# Deploy SupiVPN on Debian

Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
See [LICENSE](LICENSE) for copyright ownership and licensing terms.

One Debian 13 VM, a `.deb` metapackage, one setup file. The `supivpn` package
installs both components and provides `supivpn-setup` to configure the controller,
node and local PostgreSQL 18 database. Services run directly under systemd.
To keep PostgreSQL on another host, see the
[external database walkthrough](docs/REMOTE_DATABASE.md), including a controlled
move of an existing database. Remote setup-helper support is available from
[v0.6.1](https://github.com/SupiVPN/supivpn/releases/tag/v0.6.1); the v0.6.0 helper
configures only a local database.

This is the **minimal deployment on a single VM**, intended for evaluation and
initial validation. Production deployment documentation and infrastructure as
code (IaC) are next on the roadmap, including an **HA active-active cluster**.
The [existing cluster capabilities](docs/HA.md) describe the runtime and network
requirements; the production guide and IaC are not delivered by this walkthrough.

**Evaluation status:** the shipped VPN client template verifies the certificate
chain but does not yet enforce the server DNS name.
[DNS SAN verification](docs/TLS_CRYPT_V2.md#planned-dns-san-verification)
remains a production blocker. The helper does not remove that limitation.

The short path below establishes a split tunnel and a ping to the VPN gateway.
Private-network access is an explicit follow-up. Client Internet traffic and DNS
continue through the client's normal connection.

See the [profile ownership and two-port migration guide](docs/PROFILE_BINDING.md) for the **unreleased** account-bound profile format,
active/blocked controls, Server URL import and Linux file-import support.

## Choose your access policy

The setup file is a starting point, not the full runtime configuration.
These capabilities are already available; choose the policy you need before
opening access to private resources:

| What you want | Where to configure it and read more |
| --- | --- |
| Choose which group wins when a user belongs to several | Explicit numeric priorities in controller `groups` and agent `group_pools`. [Selection rules and paired JSON examples](docs/GROUPS.md#selection-and-policy-example). One group is selected; permissions are not combined. |
| Give groups different address capacity | One or several ordered `cidrs` per group, with independently sized, non-overlapping pools. [Pool rules](docs/IDENTITY_PROVIDER.md#pools) and [address planning](docs/HA.md#node-count-and-group-expansion). Equal pools are only a setup-helper default. |
| Limit simultaneous connections or session duration | Global defaults and per-group `max_connections_per_user` / `session_seconds`. [Session policy](docs/SESSIONS.md#policy). Connection counts span nodes and groups; a signed IdP deadline can shorten a session. |
| Let different groups reach different private services | Client routes plus firewall/ACL rules based on the assigned group CIDRs. [Worked routed-network example](docs/DEPLOYMENT_MANUAL.md#10-add-access-to-a-private-network). A route alone does not grant access. |
| Send Internet traffic or DNS through the VPN | Configure OpenVPN, forwarding/SNAT and a DNS forwarder separately. [Full tunnel](docs/HOST.md#full-tunnel) and [client DNS](docs/HOST.md#client-dns-through-the-local-node). The helper configures neither. |
| Use your SAML IdP and a convenient profile download entry | Set the groups claim and metadata; optionally add an IdP dashboard tile. [IdP requirements](docs/IDENTITY_PROVIDER.md#groups-claim) and [profile downloads](docs/PROFILES.md). Okta is the documented example, not the only SAML provider. |
| Require encrypted SAML assertions | [RSA-OAEP + AES-GCM modes, key provisioning and rollout](docs/ASSERTION_ENCRYPTION.md). Disabled by default; check the feature's release availability before configuring it. |
| Put PostgreSQL on a separate host | [Private endpoint, verified TLS, setup and existing-data cutover](docs/REMOTE_DATABASE.md). The controller supports this now; the helper extension is pending release. |
| Customize logging or grow beyond one VM | [Logging](docs/LOGGING.md#destinations-and-defaults) and [active-active architecture](docs/HA.md). The one-host helper does not provision an HA deployment. |

For the Debian file paths and a safe point to customize them, see
[configuration after setup](#customize-the-generated-configuration).
The [manual reference](docs/DEPLOYMENT_MANUAL.md) covers each installation step.
The helper's private Unix transport connects processes on one host; adding nodes
on other VMs also needs the [appropriate authenticated transport](docs/CONTROLLER_API.md#agent-authentication).

## Architecture limits to plan for

- **Existing tunnels never move between nodes.** OpenVPN sessions and IP leases
  are local to each node. After a node failure, the client reconnects and performs
  fresh SAML authorization. If it connects to another node, its VPN IP **changes**
  because node pools do not overlap; existing TCP/SSH sessions are lost. An
  active-active cluster provides alternative nodes for new connections, not
  seamless session failover. See [HA failure behavior](docs/HA.md#failure-behavior).
- **One VM has no high availability.** This minimal setup puts the VPN, controller
  and database on one host. Multiple VPN nodes alone do not make the shared
  controller and PostgreSQL highly available. Controller/database outages block
  new authorizations; an agent that cannot renew its lease in time stops its
  OpenVPN pair, disconnecting existing clients. See
  [heartbeat and fencing](docs/SESSIONS.md#heartbeat).
- **IdP membership is checked at login, not continuously.** Removing a user or
  changing groups in the IdP does not itself close an established tunnel. Neither
  heartbeat nor TLS rekey reauthorizes it. Plan session deadlines and explicit
  termination; automatic IdP-event revocation is not implemented. See
  [group changes](docs/GROUPS.md#adding-and-removing-groups) and
  [revocation limits](docs/REVOCATION.md).
- **Pool capacity is local to a group on a node.** Exhaustion rejects a new
  connection; the agent does not borrow addresses from another group or node.
  UDP load balancing does not account for individual group-pool exhaustion or
  guarantee retry on a node with free capacity. Size each group's surviving-node
  pools and connection limits for failover. See [address planning](docs/HA.md#node-count-and-group-expansion).

The upcoming minor release also includes [supivpn-cli](docs/CLI.md) for local
service status, profile administration and session termination. It is not in
the currently published 0.7 packages. Lambda uses the temporary
[profile database procedure](docs/LAMBDA_PROFILE_ADMIN.md).

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
The signed APT repository is available starting with
[v0.6.0](https://github.com/SupiVPN/supivpn/releases/tag/v0.6.0).
v0.5.0 and earlier have no `.deb` assets. A
[local build](docs/DEBIAN_PACKAGING.md#build-and-check) remains available.

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

For remote PostgreSQL, install `postgresql-client-18` in place of `postgresql-18`
and complete the [database preparation](docs/REMOTE_DATABASE.md#1-prepare-a-private-database-endpoint).
Use v0.6.1 or later for the helper extension, or the manual path on v0.6.0.

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

Group names match the verified SAML assertion exactly and are case-sensitive.
In this **setup file**, list them in your preferred priority order: the helper
writes priorities **10, 20, 30, ...** into the generated runtime files. At login,
the controller selects the matching group with the **lowest numeric priority**,
regardless of the order in the assertion. A user in both example groups gets
`admins-vpn`; their group permissions and limits are not combined. If no configured
group matches, access is denied. See the [full policy example](docs/GROUPS.md#selection-and-policy-example).

The helper initially gives each group one equal-sized pool within `10.203.0.0/24`
and uses the global defaults of one simultaneous connection and a 12-hour session.
You can customize all three after setup. The VPN network must not overlap
client LANs or destination networks. Optional setup fields: `vpn_network`, `ssh_port`
(default 22), `login_hostname` (defaults to `hostname`), and `database_name`
(default `supivpn`). A separate login hostname needs DNS and certificate coverage.
Do not put passwords or private-key contents in this file.
The optional [`database` block](docs/REMOTE_DATABASE.md#3-configure-a-fresh-vpn-vm)
selects a pre-provisioned remote writer in helper versions supporting that mode.

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

With the optional remote database block, setup instead verifies the external
writer and restricted identities, copies the public CA, and applies migrations
to the pre-provisioned empty database. It creates no local PostgreSQL cluster.

Local setup starts only its new database. Neither mode applies firewall rules,
starts the VPN or enables services at boot. Existing SupiVPN configuration, keys, node state
or its database cluster cause a refusal. After a partial failure, inspect the
reported step locally using the [manual reference](docs/DEPLOYMENT_MANUAL.md);
do not delete state or rerun setup blindly. `init` is not an upgrade command.

### Customize the generated configuration

For a fresh host, this is the point to apply your policy, **before starting the
VPN**. Keep the remaining generated settings, paths and service identities.
The richer runtime fields belong in these files, not in `supivpn-setup.json`:

| Installed file | Settings you can customize |
| --- | --- |
| `/etc/supivpn/controller/controller.json` | Allowed groups and priorities, global/per-group session and connection limits, SAML claim, public URL, profile issuance and database TLS. Since v0.7.0, it also supports the [default VPN login confirmation and explicit opt-out](docs/IDENTITY_PROVIDER.md#vpn-login-confirmation), plus [optional assertion encryption](docs/ASSERTION_ENCRYPTION.md). |
| `/etc/supivpn/node/agent.json` | Matching group policy, each group's `cidr` or `cidrs`, and the enclosing `vpn_network`. |
| `/etc/supivpn/node/openvpn.conf` | Tunnel network and client route/DNS pushes. Keep its network consistent with the agent. |
| `/etc/supivpn/firewall.nft` | Host and forwarded access for the actual group CIDRs; this candidate takes effect only when applied in step 4. |
| `/etc/supivpn/controller/client.ovpn.template` | Settings for newly downloaded profiles. Existing imported profiles do not update automatically. |

For example, give admins two connections with one-hour sessions, leave engineers
at one connection and twelve hours, and allocate two pools to admins. The
[paired controller/agent example](docs/GROUPS.md#selection-and-policy-example)
shows the exact fields. Group priorities, default limits and overrides must agree
between controller and agent. Pool sizes need not be equal; exhaustion of the
selected group's pools denies the connection instead of switching groups.
Resource access still needs the [route and ACL setup](docs/DEPLOYMENT_MANUAL.md#10-add-access-to-a-private-network).

On an existing installation, back up configuration and plan a maintenance window:
there is no live policy reload. Stop `supivpn-node` and then `supivpn-controller`
(disconnecting clients), update the matching files and network rules, then use the
[documented service sequence](docs/DEBIAN_PACKAGING.md#configuration-and-activation)
to load and check them. Do not rerun `init` or replace generated files wholesale
with examples. Group removal and pool reuse need the
[additional lifecycle precautions](docs/GROUPS.md#adding-and-removing-groups).
Readiness alone does not validate your access policy; repeat the client checks below.

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

Verify a **new SSH connection** before closing the old one. All four local-mode services
must be active; controller `/healthz` and node `/readyz` must pass with TLS
verification. If the node is still starting, wait a few seconds and run `check`
again. The OpenVPN service follows the node; do not start or enable it separately.
Remote mode checks the three SupiVPN units and the controller's database readiness;
the external database has its own service management.

## 5. Connect and finish acceptance

1. Open `https://vpn.example.test:8443/profile`, sign in through the intended IdP,
   download the profile and import it into a current OpenVPN Connect client.
   The profile contains key material; do not share or log it.
2. Connect and complete the VPN's browser login. Confirm an address from the
   assigned group pool, then `ping 10.203.0.1` (or your selected gateway).
3. Reconnect and confirm fresh SAML authorization. Test a user in each group,
   a user in both (the lower numeric priority wins), and a user without an allowed
   group (denied). Confirm the selected pool and that disallowed host/private
   services stay unreachable. For custom limits, multiple pools or routes, also
   run the [policy acceptance checks](docs/GROUPS.md#check-your-policy).
4. Record the client version/OS. A general minimum Connect version is not yet
   established; the automated VM tests use a Community client and synthetic IdP.

After acceptance, enable the dedicated database and SupiVPN at boot:

```bash
systemctl enable postgresql@18-supivpn supivpn-controller supivpn-node
```

For remote PostgreSQL, omit `postgresql@18-supivpn`; enable only the two SupiVPN
units on this VM and manage database startup on the database host.

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
the manual local procedure uses `18/main:5432` instead. In remote mode, omit the
local PostgreSQL unit from `systemctl status`; see [remote database maintenance](docs/REMOTE_DATABASE.md).

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
described in the manual database section, using the helper's cluster paths for
local PostgreSQL or your remote database provider's CA rotation procedure.

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
