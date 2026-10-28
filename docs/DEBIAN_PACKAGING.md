# Debian packages and services

Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
Licensed under AGPL-3.0-only. See [LICENSE](../LICENSE) and [COPYRIGHT.md](../COPYRIGHT.md).

These packages target Debian 13 with systemd 257 or later, on `amd64` and `arm64`.
The release workflow delivers `.deb` assets through GitHub Releases with signed
checksums and build provenance. The stable [APT repository](APT_REPOSITORY.md)
is published at `https://apt.supivpn.com`, starting with v0.6.0.
Container images below are disposable build/test environments;
container deployment is outside the plan.

For the operator walkthrough, start with [DEPLOYMENT.md](../DEPLOYMENT.md):
fresh Debian, dependency installation, one-file setup with `supivpn-setup`, service
activation, profile download and tunnel checks. This document covers packaging
implementation and automated acceptance.

## Package split

| Package | Contents | Runtime requirements |
| --- | --- | --- |
| `supivpn-node` | Agent, profile/key bootstrap CLI, dedicated agent and OpenVPN units | OpenVPN Community 2.7.8, CA certificates, systemd |
| `supivpn-controller` | Controller, explicit migration CLI, matching SQL and profile example | CA certificates, systemd, a reachable PostgreSQL 18 database |
| `supivpn-cli` (from v0.8.0) | Local root-only operator frontend; no daemon | Matching node and controller on the same host, systemd; PostgreSQL may be external |
| `supivpn` | Matching node, controller and CLI, `supivpn-setup` and its configuration templates | All three component packages, Python 3, OpenSSL, curl; PostgreSQL 18 for setup |

The controller package does not install OpenVPN or PostgreSQL. The node package
does not require a local controller; AWS transport remains available. The local
Unix transport works only on a shared host: separate packages do not imply
authenticated agent transport between arbitrary machines.

OpenVPN backward compatibility is deferred. The dependency accepts 2.7.8
distribution revisions and rejects other upstream versions until tested. Do not
force installation around this dependency. Debian's default repository may not
provide this version; provision a separately verified OpenVPN package first.
The OpenVPN package built in `ci/debian` is only a test fixture, not a supported
distribution channel. See [OpenVPN requirements](OPENVPN_UPGRADE.md).

## Release packages

The authenticated tag workflow runs the same build and lifecycle checks on native
ARM64 and AMD64 runners. Package versions derive from the tag: `v1.2.3` becomes
`1.2.3`, and `v1.2.3-rc.1` becomes `1.2.3~rc.1`, sorting before the stable version.
A deterministic changelog entry uses the tagged commit timestamp. The repository's
`UNRELEASED` changelog remains the default for local development builds.

Published 0.6/0.7 sets contain five `.deb` files: node/controller for each
architecture and one `supivpn_<version>_all.deb`. From v0.8.0,
the set contains seven, adding `supivpn-cli` for both architectures; the
metapackage pins all three component packages to its exact version. See
[CLI usage and security boundaries](CLI.md). Each set also includes `supivpn_<version>.dsc` and
`supivpn_<version>.tar.xz` with the matching vendored source. The source descriptor,
source archive and metapackage must match byte for byte across the two runners.
The OpenVPN test fixture, build caches, VM images and local configuration are
never release assets. All packages and both source files have GitHub provenance
and are covered by the release's signed `SHA256SUMS`.

Publication requires a new reviewed signed tag containing this workflow, successful
complete tag CI and the existing protected release signing step. It neither
rebuilds packages nor adds assets to old published releases. **v0.5.0 and earlier
have no Debian packages.** See [release delivery](RELEASES.md) and
[download/verification](RELEASES.md#download-and-verify-supivpn).

## Build and check

From the project checkout with the Go version in [BUILD.md](../BUILD.md) and Docker:

```sh
make deb-test ARCH=arm64
make deb-test ARCH=amd64
```

`make deb` omits the package lifecycle checks. Both commands audit source before
copying it, verify and vendor Go dependencies, then build offline inside Debian
13 using the pinned Go SDK. No home directory, credentials, Docker socket or Git
metadata enters the builder. Outputs are kept in a new `local/debian/<arch>/build-*`
directory on every run: three `.deb` files, the native source archive with vendored
dependencies, `.dsc`, `.changes`, `.buildinfo` and an input SHA-256 inventory.
These development outputs are unsigned. Distribute matching source with binaries;
the release workflow described above supplies signing/provenance for official assets.

The source package uses debhelper 13. Its build environment must supply Go 1.27.3
and `vendor/`; `debian/rules` verifies the SDK and never downloads dependencies.
The provided builder supplies this SDK explicitly because the stable Debian Go
package need not match the project. Maintainer scripts never download software.

Package checks run lintian and inspect architecture, static executables, exact
metapackage dependencies, unchanged SQL, service syntax, fresh install,
reconfiguration, reinstallation, upgrade to a higher version, removal and purge.
They also check that operator files survive and enabled units remain enabled.
Service-command wrappers verify that maintainer scripts request no service
changes on install/upgrade and stop only their own services on removal.
They run without a systemd PID 1 and
therefore do not establish running-service upgrade, boot, crash recovery,
sandbox enforcement or real tunnel acceptance. Those require a clean Debian VM.

### Disposable VM checks

```sh
make deb-vm-test ARCH=arm64
make deb-vm-test ARCH=amd64
# The same real-VM suite with PostgreSQL outside the guest:
make deb-vm-test ARCH=arm64 VM_DATABASE=remote
make deb-vm-test ARCH=amd64 VM_DATABASE=remote
# Start with TCP enabled, then exercise transport lifecycle and outages:
make deb-vm-test ARCH=arm64 VM_TRANSPORT=dual
```

This includes `deb-test`, then boots the pinned official Debian 13 generic image
with its own kernel and systemd PID 1. The host needs Docker, Go, Python 3.11 or
later, curl and OpenSSH. QEMU runs without extra container capabilities or host
devices, using software CPU emulation: each guest has two virtual CPUs, 2 GiB RAM
and a sparse 12 GiB disk. Cross-architecture runs can take several minutes.
No hypervisor or packages are installed on the development host.

The runner verifies the image's SHA-512, creates fresh test SSH identities and
pins the guest host key. Only a randomly allocated `127.0.0.1` SSH port is
published. The guest installs PostgreSQL 18 from its signed upstream APT
repository and the existing OpenVPN test fixture; setup requires Internet access.
TLS certificates, IdP signing material, database passwords and VPN keys are
generated solely for the disposable guest. No host credentials or working
configuration are mounted. Logs, disks and evidence stay under
`local/debian-vm/`; treat these as private test artifacts, not release assets.
The runner removes its own VM container on success or failure.

With `VM_DATABASE=remote`, the guest installs only `postgresql-client-18`.
A separate disposable PostgreSQL 18 container shares the QEMU runner's network
namespace and listens only on its loopback interface, with no published database
port. The guest reaches it through QEMU's gateway using `db.supivpn.test` and
`verify-full` TLS. The database is outside the guest OS and survives guest reboot;
it is removed after the run. This is test infrastructure, not a container
deployment option for SupiVPN.

Remote acceptance also rejects an incorrect CA, hostname and password before
writing configuration. Random test passwords contain spaces, quotes, backslashes
and a dollar sign, exercising the installed systemd unit's `EnvironmentFile`
parser through the running controller. No PostgreSQL server or local cluster may
appear inside the guest. Database outages use a temporary guest firewall rule
that rejects only traffic to the external test database, then removes that rule
to verify recovery. The original local mode continues to stop/start PostgreSQL
through systemd.

The VM suite verifies:

- Fresh installation leaves services stopped and not enabled.
- The installed `supivpn-setup` command creates consistent configuration, keys,
  a dedicated PostgreSQL cluster, restricted roles and migrations. Plan leaves
  the host unchanged; repeat initialization refuses to replace existing keys.
  Generated firewall syntax and certificate refresh are checked before startup.
- HTTPS readiness, verified PostgreSQL TLS and authenticated Unix transport work
  under the installed systemd units. Runtime database privileges remain restricted.
- Signed SAML profile download and VPN login assign the expected group address;
  ICMP and TCP traffic cross a real TUN device from a separate guest namespace.
- Both crash orders recover the agent/OpenVPN pair; manual stop stays stopped.
- Short controller or PostgreSQL stops preserve the current tunnel, node
  generation and service processes while new profile logins are unavailable.
  Stops lasting at least 65 seconds exceed both the agent's 40-second deadline
  and the database's 60-second lease: the old tunnel closes and cannot carry
  traffic. Restoring the dependency automatically recovers the pair with a new
  generation; the same client must complete a fresh SAML login. PostgreSQL
  recovery does not require restarting the controller. Independent outage
  scenarios begin with healthy services and reset systemd start counters left
  by earlier crash tests; no counters are reset during an outage or recovery.
- Two successive signed IdP session deadlines close only that client's tunnel.
  The same client reconnects and authenticates again, while the node stays ready
  with unchanged processes/generation and released connection slots.
- The actual processes have the configured capability bounds and
  `NoNewPrivileges`; the agent's private `/dev` does not expose TUN.
- A changed boot ID proves reboot, after which both enabled services become ready.
- Reinstall, reconfigure and an upgrade to a higher test version preserve process
  identities, enablement and operator files. Remove/purge stop only the owned
  services and retain configuration, keys, state and the controller account.

The VM suite is opt-in; ordinary CI's Debian job still runs the faster container
package checks. A successful `result.json` is written only after all VM phases
pass. It records image and package digests, database/transport mode and both boot IDs.

`VM_TRANSPORT=dual` selects a separate fresh-install acceptance path. Setup
enables TCP from its input configuration, then the suite checks disabling and
reenabling it, previously issued profiles, loss of an established UDP tunnel,
and simultaneous UDP/TCP sessions during controller/database outages. Real TLS
rekeys and independent signed session expiry must preserve the sibling tunnel
and release only confirmed closed sessions. Outage and expiry cases keep the
same client processes running; tests do not shorten installed keepalive or lease
deadlines. Rekey checks accelerate only the server interval (20 seconds for
steady traffic, 60 seconds for outages with a new browser login after recovery);
the issued client's rekey interval and handshake window remain unchanged.
Established UDP loss separately checks automatic fallback under the
default one-slot limit. A successful later manual retry does not make that
automatic-fallback check pass; see the [bounded transport retry](TRANSPORTS.md#loss-of-an-established-udp-tunnel).
The ordinary `udp` path retains its default-setup and profile-security checks.
These modes can be combined with `VM_DATABASE=remote`.

## Files and identities

Executables are installed in `/usr/sbin`, manuals in `/usr/share/man/man8`,
units in `/usr/lib/systemd/system`,
examples and licenses in `/usr/share/doc/<package>`, and inspection copies of SQL
in `/usr/share/supivpn-controller/migrations`. Setup templates are runtime data in
`/usr/share/supivpn/examples`, so systems excluding documentation can still use
the helper. SQL is also embedded in the migrator;
never edit or execute the installed SQL files individually.

Package installation creates the `supivpn-controller` system account with no login
shell or home directory. It does not create active configuration or any keys.
Configure a new combined host with the setup helper, or copy and adapt the
examples for manual installation.

| Operator-managed path | Owner and mode |
| --- | --- |
| `/etc/supivpn` | `root:root`, 0755; no secrets directly here |
| `/etc/supivpn/node` | `root:root`, 0700; files 0600 |
| `/etc/supivpn/controller` | `root:supivpn-controller`, 0750; service-readable files 0640 |
| `/etc/supivpn/controller/database.env` | `root:root`, 0600; read by systemd before switching UID |
| `/etc/supivpn/controller/migration.env` after helper setup | `root:root`, 0600; separate migration identity |
| `/etc/supivpn/keys` on a combined host | `root:supivpn-controller`, 0750 |
| `/etc/supivpn/keys/tls-crypt-v2-server.key` on a combined host | `supivpn-controller:supivpn-controller`, 0600 |

The wrapping-key loader requires mode 0600. Bootstrap into a root-owned 0700
directory using the explicit CLI key path; then apply the combined-host ownership
above. The controller can read the key; its service filesystem is read-only.
Root OpenVPN can read the same key. On a node-only host the key may remain root-owned.
No maintainer script generates, transfers, rotates or deletes working credentials.

The node unit creates `/run/supivpn` (0700) and persistent
`/var/lib/supivpn-node` (0700). The controller creates its own private
`/run/supivpn-controller` (0700). Sockets are mode 0600. Only transient runtime
directories are removed on stop. Never remove the generation journal to repair
a failed restart; follow [recovery guidance](RECOVERY.md).

## Configuration and activation

For a new combined host, `supivpn-setup` in the `supivpn` package automates
configuration, key generation, restricted database roles and migrations from
one setup JSON file. It creates a separate PostgreSQL `18/supivpn` cluster on
loopback port 55433, leaving existing clusters untouched. `plan` is read-only;
`init` is explicit and refuses existing SupiVPN files/state. Installation and
upgrade maintainer scripts never call it. It prepares firewall rules for review
and leaves SupiVPN services stopped. See [DEPLOYMENT.md](../DEPLOYMENT.md).

The optional `database` block selects a pre-provisioned remote PostgreSQL 18
writer and requires `postgresql-client-18`, without creating or managing a local
cluster. It enforces verified TLS, separate restricted runtime/migration logins
and an empty database before applying migrations. This helper extension is
pending release after v0.6.0. See [remote setup and existing-data moves](REMOTE_DATABASE.md).
`make test-setup-db ARCH=arm64` (or `amd64`) exercises real PostgreSQL TLS,
role restrictions, refusal cases, migrations and DSN escaping in a disposable
container without external networking. CI runs it on both architectures.
It does not replace real systemd/VM or provider-network acceptance.

The following paths also support [manual setup](DEPLOYMENT_MANUAL.md), a remote
database, or independently installed component packages. Do not run `init` on
an existing installation. The helper saves root-only runtime and migration
credentials separately; neither belong in support output or source control.

Use the examples under `/usr/share/doc/supivpn-node/examples/` and
`/usr/share/doc/supivpn-controller/examples/`. In particular:

- Install the agent JSON as `/etc/supivpn/node/agent.json` and the OpenVPN example
  as `/etc/supivpn/node/openvpn.conf`. Keep the management socket path identical.
- Replace the agent's `controller_uid: 0` placeholder with the actual output of
  `id -u supivpn-controller`. No fixed UID is assigned by the package. The
  controller's `agent_uid: 0` is intentional: the initial agent runs as root.
- Install controller JSON as `/etc/supivpn/controller/controller.json` and the
  client template as `/etc/supivpn/controller/client.ovpn.template`.
- Supply real certificate chains, private keys and trusted IdP metadata at the
  configured paths. Public controller URLs, TLS names and IdP registration must
  agree. The examples use HTTPS 8443, node loopback health 9443 and OpenVPN UDP 1194.
- Provision `SUPIVPN_DATABASE_URL` in the protected `database.env` using the
  restricted runtime identity; use a different owner identity for migrations.
  Match the database CA/server name. See [PostgreSQL](POSTGRES.md).
- Explicitly apply the reviewed migrations before starting the controller.
  Neither package installation nor service startup runs migrations.

After prerequisites are configured, the service sequence is:

```sh
sudo systemctl start supivpn-controller.service
# Verify controller /healthz over trusted TLS and its database-backed readiness.
sudo systemctl start supivpn-node.service
# Verify node /readyz over trusted TLS, then complete login and tunnel checks.
sudo systemctl enable supivpn-controller.service supivpn-node.service
```

Start and stop the pair through **supivpn-node.service**. OpenVPN is pulled in
automatically and has no independent enablement. Stopping only the OpenVPN unit
is not a maintenance stop: the node's `Upholds=` dependency starts it again.
Use `systemctl stop supivpn-node.service` to leave both stopped.

For the optional TCP configuration available since v0.9.0, the same node unit also
manages `supivpn-openvpn-tcp.service`. It starts only when
`/etc/supivpn/node/openvpn-tcp.conf` exists. Its `Wants=` dependency is evaluated
once per node start, avoiding continuous attempts when TCP is disabled.
An active TCP daemon's failure closes management and restarts the whole node.
Keep TCP disabled by default and
configure the [shared allocator and route hooks](TRANSPORTS.md) before enabling
it. Both transports share one agent, generation and node ID; do not run another
agent for TCP. Stop the node for maintenance so neither daemon remains active.

The agent notifies systemd after binding its management, operator and HTTPS
listeners. `After=` then allows OpenVPN to start; no fixed startup sleep or probe
consumes the management connection. In managed mode the agent allows 30 seconds
for OpenVPN to connect. This listener signal does not mean the tunnel is ready:
use `/readyz` after the controller lease and management negotiation complete.
With TCP configured, both management peers and TUN interfaces must be ready.

OpenVPN is bound to the agent and stops if it dies. Management disconnect makes
the agent exit; its rate-limited restart restores the pair. `PartOf=` propagates
explicit pair restarts and ordering stops OpenVPN first. Both units allow at
most five starts per 120 seconds. Correct the cause before using `reset-failed`.
The controller is independent and its restart does not itself stop the pair;
the existing lease-expiry behavior still applies during prolonged outages.

All examples log to stderr for journald. Inspect `journalctl -u supivpn-node`,
`-u supivpn-openvpn` and `-u supivpn-controller`; configure journal retention at
the host level. Services restrict filesystem writes and capabilities. The agent
has no NET_ADMIN or TUN access; OpenVPN has TUN and NET_ADMIN. Only the optional
TCP unit additionally receives NET_BIND_SERVICE to bind TCP/443. Packages do not
change routing, forwarding, firewall, DNS, reverse proxies or NAT.

## Upgrades and removal

Fresh installs leave services disabled and stopped. Upgrades preserve enablement
and do not stop or restart processes, run migrations, or regenerate credentials.
New files on disk do not mean the running processes have received the update.
During a planned update, review schema compatibility, migrate explicitly if
needed, then restart the controller and node in that order and verify readiness.
A node restart disconnects tunnels. Do not downgrade to a runtime incompatible
with the committed database schema or restore stale authorization state.

Removing the metapackage leaves both components intact. Mark them manually
installed with `apt-mark manual supivpn-node supivpn-controller` if retaining
them independently; otherwise a later APT autoremove can remove dependencies.
Removing the node stops only its dedicated pair; removing the controller stops
only its own unit. Purge unregisters package units but retains operator-created
configuration, secrets, persistent state and the controller account. Deliberate
decommissioning and key disposal are separate operator actions.

## Remaining deployment acceptance

VM coverage above is not a complete deployment certification. Extend the
running-service suite for repeated-failure rate limiting, unauthorized Unix
peers and broader sandbox access. The outage checks stop local services; they do
not simulate every stalled connection or network partition. Existing unit and
integration coverage of these components does not establish their complete
behavior under the installed systemd services.
Also verify group routes, return routes, metadata isolation, DNS and IPv6 behavior
for the intended network, and real IdP/client interoperability.
[DEPLOYMENT.md](../DEPLOYMENT.md) provides the first single-host operator guide;
signed package delivery remains a separate step.
See [HOST.md](HOST.md), [SECURITY_MODEL.md](SECURITY_MODEL.md) and
[systemd dependency semantics](https://manpages.debian.org/trixie/systemd/systemd.unit.5.en.html).
The package lifecycle policy uses
[dh_installsystemd](https://manpages.debian.org/trixie/debhelper/dh_installsystemd.1.en.html)
with `--no-enable --no-start --no-stop-on-upgrade`.
