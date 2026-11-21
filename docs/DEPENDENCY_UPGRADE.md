# Dependency refresh

Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
See [LICENSE](../LICENSE) for copyright ownership and licensing terms.

Reviewed on 21 November 2026. **Unreleased:** these versions describe this source
branch, not the published v0.10.0 packages. No release is scheduled by this
change. The database schema remains 12; configuration, profiles and signing
roles remain unchanged.

## Updated components

| Component | Previous | Updated |
| --- | --- | --- |
| Go build toolchain | 1.27.3 | 1.27.4 |
| OpenVPN test daemon | 2.7.8 | 2.7.9; 2.7.8 remains accepted |
| OpenVPN 3 Linux test client | 27.1 | 27.2 (`27.2-1+1.1`) |
| PostgreSQL test server | 18.6 | 18.7 |
| AWS SDK core | 1.47.3 | 1.48.0 |
| AWS config / credentials / IMDS | 1.33.9 / 1.20.9 / 1.20.3 | 1.33.21 / 1.21.3 / 1.20.9 |
| EC2 / Secrets Manager | 1.339.0 / 1.50.5 | 1.350.0 / 1.51.0 |
| Smithy | 1.28.5 | 1.28.9 |
| pgx / puddle | 5.11.0 / 2.2.3 | 5.13.0 / 2.2.4 |
| Go sync / sys / text | 0.24.0 / 0.49.0 / 0.43.0 | 0.25.0 / 0.50.0 / 0.44.0 |
| govulncheck | 1.9.0 | 1.10.0 |
| PyYAML | 6.0.3 | 6.0.4 |
| Playwright | 1.62.1 | 1.65.1 |
| setup-go / setup-node actions | 7.0.0 / 6 | 7.1.0 / 7.1.0 |
| CodeQL action | 4.39.1 | 4.39.4 |

AWS indirect modules are updated together. The declared Go module set is
unchanged. `aws-lambda-go` 1.55.1, etree 1.8.1, pgpassfile and pgservicefile are
already current. Versions and license attribution are in
[THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md). Upstream-only test/tool modules
that do not build into SupiVPN or its tests are not promoted into `go.mod` merely
to suppress update output.

Go, PostgreSQL and Debian 13 test/build images retain exact multi-architecture
digest pins. OS packages come from the signed distribution repositories when
those images are rebuilt. GitHub Actions retain full commit pins; their permissions,
publication triggers and protected signing environments are unchanged. Other
pinned actions were already current. Node tooling stays on maintained Node 24
LTS; setup-node resolves its current patch. PostgreSQL 19 adoption and migration
testing are separate work; this change updates the supported 18 series.

## Compatibility and upstream review

- [Go 1.27.4](https://go.dev/doc/devel/release#go1.27.4) includes security and
  correctness fixes. Source builds and Debian builders now use that toolchain.
- [OpenVPN review](OPENVPN_UPGRADE.md) records the signed source, relevant open
  issues, client distinctions and the bounded 2.7.8/2.7.9 version check.
- [pgx 5.13.0 changelog](https://github.com/jackc/pgx/blob/v5.13.0/CHANGELOG.md)
  includes the 5.12 security fixes for simple-protocol batches and authentication
  requirements, and 5.13 malformed-response validation. SupiVPN does not use
  simple-protocol batches. Remote deployments should still use `verify-full`:
  encryption-only `require` does not authenticate the database server.
- pgx now reloads file-backed client certificates on new TLS requests. Certificate
  and key files supplied through `sslcert`/`sslkey` must remain readable. SupiVPN
  preserves pgx's TLS configuration and does not introduce statement retries.
- [AWS SDK 1.48.0](https://github.com/aws/aws-sdk-go-v2/blob/v1.48.0/CHANGELOG.md)
  changes the default retry backoff and retry-quota accounting. Existing request
  deadlines and explicit attempt limits remain in force. A local HTTP fixture
  exercises the real Secrets Manager SDK for retry limits, access denial and
  cancellation without accessing AWS or working credentials.
- [PostgreSQL 18.7 notes](https://www.postgresql.org/docs/release/18.7/) include
  index and incremental-backup repair guidance. This PR updates disposable tests;
  it does not upgrade a working database or perform reindexing/backups.
- [OpenVPN 3 Linux 27.2](https://github.com/OpenVPN/openvpn3-linux/compare/v27.1...v27.2)
  updates its core library with a security fix. This is separate from OpenVPN
  Community 2.7.9 and from OpenVPN Connect.

## Verification and upgrade boundaries

Completed locally with Go 1.27.4:

- Unit/race, vet, PostgreSQL 18.7 integration, TLS rejection, role-isolation and
  setup-helper tests; the AWS retry/deadline fixture uses no working credentials.
- Module integrity and source/binary vulnerability checks for both Linux
  architectures, with no reported vulnerabilities. No Go modules were added.
- Independent XMLSec interoperability and two 20-second XML/SAML fuzz runs.
- Real OpenVPN 2.7.9 on ARM64 and AMD64, plus a retained 2.7.8 ARM64 image:
  SAML, bound-profile rejection, TLS failures, cancellation, expiry/rekey,
  two-node failover, shared-pool routing and UDP/TCP fallback passed.
- OpenVPN 3 Linux 27.2 profile, SAML and UDP/TCP tests on ARM64.
- Debian package build and install/reconfigure/upgrade/remove/purge checks on
  ARM64 and AMD64, plus Lambda builds for both architectures. These container
  checks do not establish booted-systemd, reboot or full VM acceptance.
- APT and artifact-signing tests with disposable keys, CI tooling tests,
  repository audit, license inventory and local documentation links.

Hosted CI runs after the approved push; its result is recorded on the PR.

Existing bound profile secrets, wrapping keys and server-name checks are
unchanged. Keep the existing keys and profiles. Do not use a dependency upgrade
as a reason to regenerate them. Updating SupiVPN does not update an independently
installed OpenVPN daemon, a client application, or a managed database.

For rollback, retain the prior SupiVPN/OpenVPN package pair and configuration;
schema 12 does not change. Drain a VPN node before changing its daemon, then
check readiness and a fresh bound login before proceeding to the next node.
Native Connect/Windows/DCO, live AWS/Okta and a full booted Debian VM were not
retested for this refresh.
