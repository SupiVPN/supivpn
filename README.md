# SupiVPN

[![Checks](https://img.shields.io/github/actions/workflow/status/SupiVPN/supivpn/checks.yml?branch=main&event=push&style=flat-square&logo=github&label=checks)](https://github.com/SupiVPN/supivpn/actions/workflows/checks.yml)
[![Latest release](https://img.shields.io/github/v/release/SupiVPN/supivpn?style=flat-square&color=16a34a&label=release)](https://github.com/SupiVPN/supivpn/releases/latest)
[![Go version](https://img.shields.io/github/go-mod/go-version/SupiVPN/supivpn?style=flat-square&logo=go&logoColor=white)](go.mod)
[![License: AGPL-3.0-only](https://img.shields.io/badge/license-AGPL--3.0--only-2563eb?style=flat-square)](LICENSE)
[![Linux ARM64 and AMD64](https://img.shields.io/badge/linux-arm64%20%7C%20amd64-475569?style=flat-square&logo=linux&logoColor=white)](docs/RELEASES.md)

Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
Licensed under [AGPL-3.0-only](LICENSE). Copyright ownership: [COPYRIGHT.md](COPYRIGHT.md).

SupiVPN combines a separate OpenVPN Community 2.7.8 process, a Go agent, and
a SAML authorization controller. Client profiles include `tls-crypt-v2`;
no client certificate is required. A verified SAML assertion determines access
and group membership.

The controller runs as an HTTP service on a VM or behind AWS API Gateway and
Lambda. Both modes use PostgreSQL 18 and the same authorization logic.
AWS adapters are isolated from SAML, IP allocation, and profile issuance.

## Features

- SP-initiated SAML login from an existing OpenVPN client and browser profile downloads.
- Assertion-based groups, explicit priorities, and one or more IP pools per group and node.
- Active-active nodes with separate address pools and a shared `tls-crypt-v2` wrapping key.
- Reconnection after node failure with a new SAML login and IP; existing TCP sessions are lost.
- Group limits on session count and duration; expiry disconnects the tunnel and requires a new SAML login.
  Explicit unlimited mode and its risks are documented in [SESSIONS.md](docs/SESSIONS.md).
- Shared PostgreSQL state, replay protection, separate migrations, and database reconnection.
- Structured JSON events with configurable file/stream output and bounded local rotation:
  [logging and collection](docs/LOGGING.md).
- Routing to private resources while preserving group IP addresses. The deployment
  configures full tunnel routing, NAT, DNS, return routes, and network rules.

## Structure

SupiVPN is a single Go module rooted at `go.mod`. All commands are under
`cmd/`; implementation packages are private to this module under `internal/`.
Run Go and Make commands from the repository root.

| Directory / file | Purpose |
| --- | --- |
| `cmd/supivpn/` | Thin VPN agent entry point |
| `cmd/supivpn-*/` | Controller, Lambda, migration, profile and packaging commands |
| `internal/agent/` | Agent logic and its colocated unit/integration tests |
| `internal/controller/`, `internal/saml/` | Authorization and SAML verification |
| `internal/postgres/` | Database access and embedded, immutable SQL migrations |
| Other `internal/` packages | Transport and platform adapters, profile issuance |
| `examples/` | Public configuration and client profile templates |
| `testdata/` | Container definitions for independent interoperability tests |
| `docs/` | Architecture, operations, security and release documentation |
| `ci/`, `tools/` | CI configuration and repository/release tooling |
| `local/`, `out/` | Caches, build and CI outputs |
| [BUILD.md](BUILD.md), [DEVELOPERS.md](DEVELOPERS.md) | Build/test commands and contributor setup |

Start with [architecture](docs/ARCHITECTURE.md), [runtime commands](docs/RUNTIME.md),
[host requirements](docs/HOST.md), [controller](docs/CONTROLLER.md),
[database](docs/DATABASE.md), [security model](docs/SECURITY_MODEL.md), or
[release delivery](docs/RELEASES.md).

The layout follows Go's [server project guidance](https://go.dev/doc/modules/layout)
and [single-module repository guidance](https://go.dev/doc/modules/managing-source).
Tests live beside the packages they exercise. Embedded OpenVPN fixtures live in
`internal/agent/testdata/`.
The module has no `go.work` and no public library API.

Build components with Make or download a versioned release. See
[CONTRIBUTING.md](CONTRIBUTING.md) for local development and
[release delivery](docs/RELEASES.md) for artifact verification.

## Getting started

1. Run `make build` or build a single component as described in [BUILD.md](BUILD.md).
2. Prepare PostgreSQL and the owner/runtime/migrator roles; apply migrations
   before starting the controller.
3. Define public VPN/HTTPS endpoints, TLS certificates, nodes, groups,
   non-overlapping IP pools, routes, and DNS.
4. Deploy the controller and agents with consistent group policies.
   For a cluster, deliver the same wrapping key to every node and the profile service.
5. Configure the [SAML IdP](docs/IDENTITY_PROVIDER.md) and its
   [profile download tile](docs/PROFILES.md), then test successful and rejected logins.
   A direct `<public_url>/profile` link also works; a Bookmark App is optional.
6. Run the [cluster checks](docs/HA.md#checks) in your environment.

`example.test`, group names, and addresses in the documentation are examples.
Replace them with your own values and check for network overlaps before deployment.
[Architecture](docs/ARCHITECTURE.md) describes both deployment modes.

## Current limitations

Production readiness is assessed against the [security model](docs/SECURITY_MODEL.md).
Open tasks include VPN server DNS SAN verification with OpenVPN Connect and an
independent audit of the custom SAML/XMLDSig implementation.
PostgreSQL `verify-full`, including a separate TLS server name for connection
aliases, is implemented but must be enabled explicitly; the default `require`
encrypts traffic without verifying server identity. See [database TLS](docs/DATABASE.md).

Bounded EC2 stop/start recovery is implemented. Automatic VM replacement, ASG,
and rolling updates belong to the infrastructure deployment, not this checkout.
Wrapping key rotation with overlap and individual profile revocation are not implemented.
Local tests do not guarantee the behavior of a specific load balancer, routing setup, or IdP.

Findings R1-R3 are fixed; maintenance and controlled recovery from blocked
are documented in [RECOVERY.md](docs/RECOVERY.md). Cloud acceptance tests and the
blockers in [SECURITY_MODEL.md](docs/SECURITY_MODEL.md) remain before production.

The current client template does not yet verify the VPN server name.
It checks the CA, validity period, and certificate purpose. Server name
verification must be added before production; `tls-crypt-v2` does not replace it.

## License and new files

Original SupiVPN materials use [AGPL-3.0-only](LICENSE).
Copyright remains with Stanislav Kazachkov; see [COPYRIGHT.md](COPYRIGHT.md).
OpenVPN, Go, and third-party dependencies retain their own licenses:
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

The product name is **SupiVPN**; technical identifiers use `supivpn`.
New original source files include copyright and
`Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.`
SPDX: `AGPL-3.0-only`.
COPYRIGHT.md defines the scope of the license. Retain third-party notices.

## Repository language

Write all documentation, comments, and repository text in English.
Do not include literal Cyrillic or Han characters in repository files or filenames.
Unicode test inputs must use language-appropriate escapes without changing
the values exercised at runtime.
