# Debian deployment plan

Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
Licensed under AGPL-3.0-only. See [LICENSE](LICENSE) and [COPYRIGHT.md](COPYRIGHT.md).

This is the plan for the first guided installation: a clean Debian 13 server
running SupiVPN through `.deb` packages and systemd. It is not yet an executable
installation guide. The packages, systemd units and complete Debian procedure
have not been implemented or validated; current releases do not gain those
artifacts from this document.

## Intended installation

- `supivpn-node`: node agent, OpenVPN integration and node service units.
- `supivpn-controller`: controller, database migrator and controller service unit.
- `supivpn`: metapackage installing both components at matching versions.

The first supported walkthrough will run one node and one controller on the
same `amd64` or `arm64` Debian host. PostgreSQL 18 can be local or remote.
The controller package will not force installation of a local database server.
The [package and service design](docs/DEBIAN_PACKAGING.md) specifies paths,
ownership, permissions, service lifecycle and implementation order.

Package separation is not yet support for arbitrary node/controller placement.
The VM controller has a private Unix agent endpoint; wiring this transport into
the agent's runtime configuration remains part of the implementation. Do not
substitute the isolated in-memory agent mode for the shared PostgreSQL design.

## Walkthrough to implement and verify

Each stage will include exact commands, complete example files, expected
results and a short failure check. No stage may require a cloud account for
the local Debian scenario.

| Stage | What the guide will provide | Acceptance evidence |
| --- | --- | --- |
| 1. Prepare the host | Supported Debian/architecture, patched OpenVPN package, time synchronization, DNS, non-overlapping client/network ranges and required ports | Correct versions; reachable intended endpoints; no accidental public management or database listener |
| 2. Install packages | Verified package/source downloads and dependency installation; services remain stopped | Package contents, identities and permissions match the design; no keys or database state created by APT |
| 3. Prepare PostgreSQL | One straightforward local database example, plus remote database/TLS differences; separate owner, runtime and migrator roles | Runtime cannot perform DDL or become the owner; remote CA/hostname checks succeed and reject a wrong server |
| 4. Apply migrations | An explicit invocation using the migration identity, with schema/digest checks and upgrade notes | Successful migration; repeat invocation is safe; controller startup performs no migration |
| 5. Configure identity and TLS | Domain/certificate paths, standard SAML IdP settings, groups and session policy | Metadata/ACS/audience agree; certificates validate; no credentials or assertions appear in logs |
| 6. Configure profiles and the node | Explicit one-time wrapping-key bootstrap/provisioning, profile template, local controller transport, persistent agent state and matching IP pools | Key remains unchanged on rerun; profile contains only its own client key; unauthorized local peers are rejected |
| 7. Configure the network | A concrete split-tunnel example with forwarding, nftables, client routes and return routes; separate optional full-tunnel/DNS instructions | Allowed resources reachable; group isolation, metadata restrictions and unwanted VPN-to-VPN traffic rejection verified |
| 8. Activate services | Controller first, then the coordinated agent/OpenVPN pair; socket readiness and health checks | Healthy database-backed controller and ready node, then a successful SAML login and actual VPN traffic |
| 9. Exercise failure cases | Denied/no-group login, expiry, reconnect, process failure, database outage and reboot | No authorization bypass; bounded failure/recovery; persistent generation state survives reboot |
| 10. Maintain the installation | Backup, certificate renewal, explicit service activation after upgrades, compatible rollback, removal and deliberate decommissioning | Configuration/keys survive package operations; no automatic database rollback, key rotation or unrelated service changes |

Public configuration examples use fictional domains, groups and networks.
The final walkthrough must replace all example values together, including
certificate names, IdP settings, public URLs, node identity and address pools.
Credentials are entered through a private provisioning mechanism, never copied
from documentation or placed in command history.

## Existing references and limits

Until the walkthrough is implemented, these documents describe the current
components and checks:

- [Build and verification](BUILD.md) and [release verification](docs/RELEASES.md).
- [Host and routing requirements](docs/HOST.md), [controller](docs/CONTROLLER.md)
  and [agent API](docs/CONTROLLER_API.md).
- [Database roles](docs/DATABASE.md), [migrations and TLS](docs/POSTGRES.md).
- [Identity provider](docs/IDENTITY_PROVIDER.md), [profile downloads](docs/PROFILES.md)
  and [wrapping-key handling](docs/TLS_CRYPT_V2.md).
- [Sessions](docs/SESSIONS.md), [recovery](docs/RECOVERY.md),
  [logging](docs/LOGGING.md) and [security acceptance](docs/SECURITY_MODEL.md).

The current client template does not verify the VPN server's DNS identity.
That existing production blocker, independent SAML review and live network
acceptance remain required; packaging alone does not close them.
OpenVPN version compatibility also needs implementation and integration tests
before replacing the current 2.7.8 requirement with a supported version range.

## Later deployment work

After the Debian path, prepare a public Terraform module for the AWS/Lambda
mode, split into submodules with explicit mandatory and optional components.
Then provide a Terragrunt stack for a new AWS account and an alternative using
CloudFormation with reusable nested stacks. Account/bootstrap prerequisites,
costs and deployment permissions must be documented before presenting either
as a one-command installation.

The Lambda design still needs VPN compute nodes and PostgreSQL; it does not
move VPN traffic into Lambda. Disabling automatic recovery does not by itself
make every recovery/cleanup component optional. Decide those boundaries from
the runtime requirements and tests.
Container deployment is outside the current plan.
