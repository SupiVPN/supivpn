# Debian packages and services

Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
Licensed under AGPL-3.0-only. See [LICENSE](../LICENSE) and [COPYRIGHT.md](../COPYRIGHT.md).

These local development packages target Debian 13 with systemd 257 or later,
on `amd64` and `arm64`. They are not yet published release assets or an APT
repository. Container images below are disposable build/test environments;
container deployment is outside the plan.

## Package split

| Package | Contents | Runtime requirements |
| --- | --- | --- |
| `supivpn-node` | Agent, profile/key bootstrap CLI, dedicated agent and OpenVPN units | OpenVPN Community 2.7.8, CA certificates, systemd |
| `supivpn-controller` | Controller, explicit migration CLI, matching SQL and profile example | CA certificates, systemd, a reachable PostgreSQL 18 database |
| `supivpn` | Metapackage depending on both components at the same package version | Both component packages |

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
release signing/provenance and publishing remain a separate implementation step.

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

The VM suite verifies:

- Fresh installation leaves services stopped and not enabled.
- The installed examples work with explicit migration, a restricted database
  runtime identity, verified PostgreSQL TLS and authenticated Unix transport.
- Signed SAML profile download and VPN login assign the expected group address;
  ICMP and TCP traffic cross a real TUN device from a separate guest namespace.
- Both crash orders recover the agent/OpenVPN pair; manual stop stays stopped.
- The actual processes have the configured capability bounds and
  `NoNewPrivileges`; the agent's private `/dev` does not expose TUN.
- A changed boot ID proves reboot, after which both enabled services become ready.
- Reinstall, reconfigure and an upgrade to a higher test version preserve process
  identities, enablement and operator files. Remove/purge stop only the owned
  services and retain configuration, keys, state and the controller account.

The VM suite is opt-in; ordinary CI's Debian job still runs the faster container
package checks. A successful `result.json` is written only after all VM phases
pass. It records image and package digests and both boot IDs.

## Files and identities

Executables are installed in `/usr/sbin`, manuals in `/usr/share/man/man8`,
units in `/usr/lib/systemd/system`,
examples and licenses in `/usr/share/doc/<package>`, and inspection copies of SQL
in `/usr/share/supivpn-controller/migrations`. SQL is also embedded in the migrator;
never edit or execute the installed SQL files individually.

Package installation creates the `supivpn-controller` system account with no login
shell or home directory. It does not create active configuration or any keys.
The examples must be copied and adapted by the operator.

| Operator-managed path | Owner and mode |
| --- | --- |
| `/etc/supivpn` | `root:root`, 0755; no secrets directly here |
| `/etc/supivpn/node` | `root:root`, 0700; files 0600 |
| `/etc/supivpn/controller` | `root:supivpn-controller`, 0750; service-readable files 0640 |
| `/etc/supivpn/controller/database.env` | `root:root`, 0600; read by systemd before switching UID |
| `/etc/supivpn/keys` on a combined host | `root:supivpn-controller`, 0750 |
| `/etc/supivpn/keys/tls-crypt-v2-server.key` on a combined host | `supivpn-controller:supivpn-controller`, 0600 |

The wrapping-key loader requires mode 0600. Bootstrap into a root-owned 0700
directory using the explicit CLI key path; then apply the combined-host ownership
above. The controller can read the key; its service filesystem is read-only.
Root OpenVPN can read the same key. On a node-only host the key may remain root-owned.
No package script generates, transfers, rotates or deletes working credentials.

The node unit creates `/run/supivpn` (0700) and persistent
`/var/lib/supivpn-node` (0700). The controller creates its own private
`/run/supivpn-controller` (0700). Sockets are mode 0600. Only transient runtime
directories are removed on stop. Never remove the generation journal to repair
a failed restart; follow [recovery guidance](RECOVERY.md).

## Configuration and activation

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

The agent notifies systemd after binding its management, operator and HTTPS
listeners. `After=` then allows OpenVPN to start; no fixed startup sleep or probe
consumes the management connection. In managed mode the agent allows 30 seconds
for OpenVPN to connect. This listener signal does not mean the tunnel is ready:
use `/readyz` after the controller lease and management negotiation complete.

OpenVPN is bound to the agent and stops if it dies. Management disconnect makes
the agent exit; its rate-limited restart restores the pair. `PartOf=` propagates
explicit pair restarts and ordering stops OpenVPN first. Both units allow at
most five starts per 120 seconds. Correct the cause before using `reset-failed`.
The controller is independent and its restart does not itself stop the pair;
the existing lease-expiry behavior still applies during prolonged outages.

All examples log to stderr for journald. Inspect `journalctl -u supivpn-node`,
`-u supivpn-openvpn` and `-u supivpn-controller`; configure journal retention at
the host level. Services restrict filesystem writes and capabilities. The agent
has no NET_ADMIN or TUN access; OpenVPN has TUN and NET_ADMIN. Packages do not
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
running-service suite for repeated-failure rate limiting, prolonged controller
and database outages, unauthorized Unix peers, broader sandbox access and session
expiry/reconnect. Existing unit and integration coverage of these components does
not establish their complete behavior under the installed systemd services.
Also verify group routes, return routes, metadata isolation, DNS and IPv6 behavior
for the intended network, and real IdP/client interoperability. A complete
operator deployment guide and signed package delivery remain separate steps.
See [HOST.md](HOST.md), [SECURITY_MODEL.md](SECURITY_MODEL.md) and
[systemd dependency semantics](https://manpages.debian.org/trixie/systemd/systemd.unit.5.en.html).
The package lifecycle policy uses
[dh_installsystemd](https://manpages.debian.org/trixie/debhelper/dh_installsystemd.1.en.html)
with `--no-enable --no-start --no-stop-on-upgrade`.
