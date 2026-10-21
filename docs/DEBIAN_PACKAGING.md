# Debian packages and services

Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
Licensed under AGPL-3.0-only. See [LICENSE](../LICENSE) and [COPYRIGHT.md](../COPYRIGHT.md).

Status: agreed packaging design; package recipes, service units and Debian
installation tests are not implemented yet. This document defines the first
implementation steps. It does not add `.deb` files to existing releases.
The operator-facing sequence is in [DEPLOYMENT.md](../DEPLOYMENT.md).

## Target and package split

The initial target is Debian 13 with systemd, on `amd64` and `arm64`.
The first complete installation places one VPN node and one controller on the
same host. PostgreSQL 18 may run locally or on a separate database server.
Container deployment is outside this plan; isolated containers remain useful
for existing development tests.

| Package | Contents | Dependencies and boundaries |
| --- | --- | --- |
| `supivpn-node` | Agent, `supivpn-profile` key/bootstrap CLI, OpenVPN example, agent and OpenVPN systemd units | OpenVPN as a separate distribution package, CA certificates and the system service tools used by the package; no PostgreSQL or controller package dependency |
| `supivpn-controller` | Controller, `supivpn-migrate`, matching SQL sources, profile template and controller systemd unit | CA certificates and system service tools; a reachable PostgreSQL 18 database is a runtime requirement, not a dependency on a local PostgreSQL server package |
| `supivpn` | Metapackage with documentation and dependencies on both component packages at its own exact package version | No duplicate executables, configuration, secrets or services |

Build both component packages from the same source revision. Independent
component installation remains possible; supported mixed versions must be
documented and tested before allowing a rolling upgrade. The metapackage keeps
the initial installation aligned, but does not perform migration or activation.
Removing the metapackage alone must not stop either component; document APT
autoremove behavior and how to retain independently needed component packages.

`supivpn-profile` belongs to the node package because its local key generation
uses the OpenVPN executable. Browser profile issuance is already part of the
controller and does not invoke OpenVPN. A controller-only host receives its
wrapping key through the operator's provisioning process.

## Current implementation gaps

These must be addressed before documenting a working Debian installation:

1. **Local agent transport.** The VM controller implements a private Unix agent
   socket with kernel peer-UID checks. However, the agent's
   [`startRemote`](../internal/agent/remote_agent.go) currently constructs an
   HTTPS client with an EC2/SigV4 signer, and its configuration requires an AWS
   region. [`agentclient.New`](../internal/agentclient/client.go) accepts an
   injected transport, but the agent command does not yet expose the Unix
   transport through configuration. Add explicit local transport selection,
   preserve node/generation/session validation, and test that this mode neither
   loads AWS credentials nor falls back to in-memory authorization. Separate
   packages do not imply authenticated controller communication between hosts:
   the VM HTTPS listener does not serve the agent API.
2. **OpenVPN compatibility.** The profile CLI requires exactly 2.7.8, and the
   agent expects an acknowledgement for `version 5` that older servers do not
   send. Resolve both before broadening supported versions. The functional
   protocol floor is 2.6.2: management version 5 adds the required key ID to
   `client-pending-auth`. The existing `disable-dco` option requires 2.6 or later.
   Keep a separate security-update policy: a feature-compatible historical
   version is not automatically suitable for installation. Determine the Debian
   dependency range from tested, patched packages, including distribution
   backports of fixes. Keep exact CI versions for reproducibility.
3. **Local lifecycle and recovery.** Exercise durable generation recovery,
   lease expiry and session-slot handling with the local controller. Existing
   EC2 recovery must not become an implicit dependency of a Debian host. Document
   the local maintenance/recovery procedure, including ambiguous disconnects;
   never clear slots or generations directly in SQL to make a restart succeed.
4. **Production acceptance.** Packaging does not resolve the existing VPN
   server-name verification, independent SAML review and deployment checks in
   [SECURITY_MODEL.md](SECURITY_MODEL.md). Keep these visible in the installation
   guide rather than treating package installation as production approval.

Source evidence for OpenVPN: [2.6.2 changes](https://github.com/OpenVPN/openvpn/blob/v2.6.2/Changes.rst)
and [2.7.1 management acknowledgement changes](https://github.com/OpenVPN/openvpn/blob/v2.7.1/Changes.rst).
The previously tested version is recorded in [OPENVPN_UPGRADE.md](OPENVPN_UPGRADE.md).
OpenVPN Connect acceptance must cover profile import, browser login, traffic,
rekey, expiry and reconnect for each supported platform; the Community CLI
test fixture is not proof of an unchanged profile working in every client.

## Installed files

The paths below are packaging targets, not paths already installed by SupiVPN.
Use explicit configuration arguments and update packaged examples together;
existing binary defaults and infrastructure examples must not be changed silently.

| Package | Target path | Purpose |
| --- | --- | --- |
| node | `/usr/sbin/supivpn` | Agent and its existing `-learn-address` mode |
| node | `/usr/sbin/supivpn-profile` | Explicit key bootstrap/local profile issuance |
| node | `/usr/lib/systemd/system/supivpn-node.service` | Agent lifecycle and private runtime/state directories |
| node | `/usr/lib/systemd/system/supivpn-openvpn.service` | Dedicated OpenVPN process using the SupiVPN configuration |
| controller | `/usr/sbin/supivpn-controller` | Controller process |
| controller | `/usr/sbin/supivpn-migrate` | Explicit database migration operation |
| controller | `/usr/share/supivpn-controller/migrations/` | SQL matching the migrator's embedded sources; never edited or executed individually |
| controller | `/usr/lib/systemd/system/supivpn-controller.service` | Controller lifecycle and private runtime directory |
| each | `/usr/share/doc/<package>/` | License, applicable dependency notices, deployment instructions and examples |

Ship example files under each component's documentation directory. Installation
does not copy them into active configuration. The future setup procedure creates
the following operator-managed files; subsequent package upgrades preserve them.

| Path | Owner and mode | Use |
| --- | --- | --- |
| `/etc/supivpn/` | `root:root`, 0755 | Parent directory; no secrets directly in this directory |
| `/etc/supivpn/node/` | `root:root`, 0700 | `agent.json`, `openvpn.conf`, node TLS files and trusted IdP metadata |
| `/etc/supivpn/node/agent.json`, `openvpn.conf` | `root:root`, 0600 | Explicit inputs to the node units; OpenVPN `learn-address` uses `/usr/sbin/supivpn -learn-address` |
| `/etc/supivpn/controller/` | `root:supivpn-controller`, 0750 | Controller configuration, TLS files, database CA and profile template |
| Controller configuration and public material | `root:supivpn-controller`, 0640 | Service-readable, operator-writable inputs |
| Controller TLS private key | `root:supivpn-controller`, 0640 | Service read access; no access for other users |
| `/etc/supivpn/controller/database.env` | `root:root`, 0600 | Runtime `SUPIVPN_DATABASE_URL`, read by systemd before changing service UID; no migration credentials |
| `/etc/supivpn/keys/` | `root:supivpn-controller`, 0750 on a combined host | Operator-managed wrapping-key directory, read-only inside service sandboxes |
| `/etc/supivpn/keys/tls-crypt-v2-server.key` | `supivpn-controller:supivpn-controller`, 0600 on a combined host | One wrapping key read by the controller and root OpenVPN process |
| `/run/supivpn/` | `root:root`, 0700 | Agent-created `management.sock` and `operator.sock`, each 0600 |
| `/run/supivpn-controller/` | `supivpn-controller:supivpn-controller`, 0700 | Controller-created `agent.sock`, 0600 |
| `/var/lib/supivpn-node/` | `root:root`, 0700 | Persistent agent generation journal; never under `/run` |

The wrapping-key loader currently requires a regular file with mode **0600**;
making it group-readable is not a valid solution. On a node-only host the key
and its private parent can instead be owned by root, without creating a
controller account. Native key bootstrap also requires a 0700 parent: initialize
in a root-owned 0700 directory, then explicitly apply the combined-host directory
and file ownership above. The setup procedure must pass the chosen key path to
the CLI; its current default points elsewhere. On a combined host the controller owns the key file so it
can read it, while the root-owned parent and read-only service namespace prevent
replacement and service-side writes. Verify this in the sandbox tests.
All consumers must use the same operator-provisioned key; package scripts never
generate, copy, rotate, delete or print it.

Private keys, database environments and generated profiles are never package
payloads or public examples. Generated client profiles remain mode 0600 outside
package-managed documentation. Keep backups of configuration and keys separate
from disposable build outputs.

## Service identities and isolation

- The controller uses a dedicated system user/group `supivpn-controller`, with
  no login shell or interactive home. Allocate its UID through Debian's system
  account mechanism; never assume a fixed numeric UID or reuse an unrelated
  existing account. Keep the account on removal so retained files cannot pass to
  a newly allocated user.
- The initial node agent runs as root to reach the controller's private 0700
  directory/0600 socket; set the controller's `agent_uid` explicitly to 0.
  The agent does not need TUN access or network-administration capabilities.
  Restrict its capabilities to those proven necessary for local socket access.
  Using a dedicated agent UID later requires an explicit change to the current
  socket access model; do not weaken permissions to 0777/0666.
- OpenVPN runs as a separate root process, with only the capabilities needed for
  TUN/routing and reading the configured keys. Test capability restrictions
  against the learn-address helper, reconnect and shutdown paths before shipping
  the units. OpenVPN receives no database credentials.
- Use `UMask=0077`, `NoNewPrivileges=yes`, filesystem protection and explicit
  writable paths. The controller needs no access to TUN or agent state. Keep
  config/key paths read-only in all service sandboxes. Persistent node state
  must remain writable and must survive restarts and package upgrades.
- Packaged examples select `logging.output=stderr` for journald explicitly;
  otherwise the existing VM default writes files. Document journal access and
  retention. Optional file logging needs separate service-owned directories and
  the application's existing retention controls. Never include raw SAML,
  tickets, profiles, keys or database connection strings in diagnostics.

Use distinct listeners: controller HTTPS on 8443 by default, node health HTTPS
on loopback 9443, and OpenVPN UDP 1194. The real public URLs, certificate names
and IdP endpoints must agree; a reverse proxy/port 443 is optional. Packages do
not install or reconfigure a proxy, firewall, DNS resolver, forwarding or NAT.

## Startup, failure and shutdown

The agent and OpenVPN are a lifecycle pair. The controller is an independent
service, and a controller restart must not blindly restart established tunnels.
Do not bind the node package unconditionally to a local controller unit: a
node-only installation can use the existing AWS deployment mode.

For the first combined-host installation:

1. Provision configuration, credentials, certificates and the wrapping key.
   Configure database access and apply migrations explicitly.
2. Start the controller and verify its database-backed health and private agent
   socket. A running process or open HTTPS port is not enough.
3. Start the node agent, which creates its management socket. OpenVPN may start
   only after this socket is actually available; systemd `After=` by itself
   does not establish application readiness. Use a bounded readiness mechanism,
   not a fixed startup sleep, and propagate startup failure.
4. Start OpenVPN in the foreground with `management-client` and
   `management-hold`. The agent negotiates management, recovers/rotates its
   persistent generation, establishes its controller lease, then releases hold.
5. Check node `/readyz` and complete a real client login and traffic test.

The node unit must own its runtime directory, and the controller unit must own
its separate directory. Remove stale sockets only after all owning processes
have stopped. Never delete another process's socket to force startup.

If the agent dies, stop OpenVPN before starting a new pair; no tunnel may outlive
its authorizing agent. If OpenVPN dies, the existing agent exits on management
disconnect and the pair must recover together. Use bounded, rate-limited restart
behavior and test both failure orders, repeated failures and simultaneous unit
jobs. A unit dependency diagram alone does not establish that restart works.
Manual stop must leave the pair stopped. During shutdown stop OpenVPN before
the agent and remove only transient sockets; retain the generation journal.

## Package lifecycle

Use standard Debian packaging and debhelper for package metadata and service
integration. Keep all three packages in one source package. Build with the Go
version and verified dependencies in [BUILD.md](../BUILD.md); build tools are
not runtime dependencies and maintainer scripts never download software.

| Operation | Required behavior |
| --- | --- |
| Fresh install/configure | Install files, create only required system accounts, register units; leave services disabled and stopped until explicitly configured and activated |
| Upgrade | Preserve operator files, secrets, state and enablement; do not automatically stop/restart the VPN pair, run migrations or regenerate keys |
| Explicit activation/update | Validate prerequisites, run any reviewed migration with its separate identity, then start/restart in the documented order and verify readiness |
| Remove component | Stop only its services using Debian service helpers; removing the node stops both agent and its dedicated OpenVPN process; never stop unrelated OpenVPN instances or PostgreSQL |
| Purge | Remove package-owned files and service registration; retain operator-provisioned secrets/configuration, persistent node state and system identities; describe separate deliberate decommissioning |

Review generated maintainer scripts as well as source recipes. With debhelper,
configure both no-enable and no-start behavior, plus the no-stop-on-upgrade
policy; verify actual install, upgrade, remove and purge effects, including
`policy-rc.d`, interrupted operations and repeated configuration.
See [Debian maintainer-script guidance](https://www.debian.org/doc/debian-policy/ch-maintainerscripts.html)
and [dh_installsystemd](https://manpages.debian.org/trixie/debhelper/dh_installsystemd.1.en.html).

Migration SQL stays embedded in the matching migrator; installed SQL is for
inspection and digest verification. The daemon's restricted database login
must never acquire owner/migration privileges. Neither service startup nor
APT hooks run `supivpn-migrate`. After a committed migration, rollback is only
to a runtime compatible with the resulting schema; no automatic down migration
or restoration of stale authorization state. Follow [POSTGRES.md](POSTGRES.md).

An upgrade leaves running processes on their existing executable until the
operator activates the update. State this clearly in the guide: new files on
disk are not evidence that patched processes are serving traffic. Decide and
document restart timing as part of the maintenance procedure.

## Implementation and acceptance sequence

1. Wire and test the agent's local Unix transport and local recovery behavior.
   Resolve OpenVPN version handling; document tested server/client combinations.
2. Add package recipes, complete examples, system users and systemd units using
   the layout above. Include per-package notices and matching source delivery;
   integrate local builds before changing any release publication workflow.
3. Check package contents/dependencies, executable architecture, migration
   digests, unit syntax, permissions and maintainer-script behavior on both
   architectures. Confirm that a controller-only install does not pull OpenVPN
   or a local database, and node-only installation does not pull the controller.
4. Use a clean disposable Debian 13 VM with systemd for install, explicit
   activation, cold boot, upgrades, failure recovery, removal and purge. Test
   configuration/key preservation, rejected unauthorized Unix peers, service
   sandboxing and real SAML/tunnel traffic. Container-only checks do not prove
   host boot, systemd lifecycle, routing or firewall behavior.
5. Complete the copyable configuration examples and verified commands in
   [DEPLOYMENT.md](../DEPLOYMENT.md), with expected outcomes and troubleshooting.
   Record actual versions and results; leave untested scenarios explicit.
6. Add signed `.deb` delivery and provenance to the release process, followed by
   an APT repository if needed. Publishing packages or provisioning test VMs is
   separate from preparing source and local tests.

The first guide must cover successful login, denied groups, session expiry,
reconnect, controller/database outages, both process-crash orders, reboot,
upgrade and rollback limits. Also verify group routing, return routes, metadata
isolation, DNS and IPv6 behavior for the selected network mode. Existing
[host](HOST.md), [HA](HA.md) and [security](SECURITY_MODEL.md) checks remain inputs.
