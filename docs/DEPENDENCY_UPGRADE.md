# Dependency upgrade for v0.4.1

Reviewed on 20 October 2026. The database schema remains at version 9 and the
release bundle contract remains at version 3. No application configuration
migration is required. Developers and source builders need Go 1.27.3 or newer.

## Updated components

| Component | Version | Review |
| --- | --- | --- |
| Release/CI Go toolchain | 1.27.3 | Latest stable release at review time. CI reads the minimum from `go.mod`; the official container image remains digest-pinned. |
| AWS SDK core | 1.47.3 | Updated together with its config and service modules. |
| AWS config / credentials / IMDS | 1.33.9 / 1.20.9 / 1.20.3 | Stable updates within the existing module major versions. |
| EC2 / Secrets Manager clients | 1.339.0 / 1.50.5 | Existing recovery operations remain covered by tests. |
| Smithy | 1.28.5 | Updated with the AWS SDK dependency graph. |
| Go sync / sys / text | 0.24.0 / 0.49.0 / 0.43.0 | Latest stable versions of the declared modules. |
| govulncheck | 1.9.0 | Updated scanner; its vulnerability database is refreshed when it runs. |
| Local Python audit | PyYAML 6.0.3 | Pinned installation through `make setup` in a local virtual environment. |
| Disposable PostgreSQL / OpenVPN | 18.6 / 2.7.8 | Already current; retain the verified image/source pins. Production components are managed separately. |
| XMLSec test base | Debian 13 slim | Pin the current official multi-architecture image digest. |

`pgx/v5` 5.11.0, `aws-lambda-go` 1.55.1, etree 1.8.1 and puddle 2.2.3 were
already current. No declared module is retracted. Full versions and retained
license texts are in [THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md) and
[THIRD_PARTY_LICENSES.txt](../THIRD_PARTY_LICENSES.txt). The 32 retained module
license/notice paths were checked against the updated module cache; their text
is unchanged. The Go 1.27.3 SDK notices are also covered by the retained texts.

The full module graph lists newer versions of `kr/pretty`, `objx`, `testify`,
`x/mod` and `x/tools`. These are upstream test/unused graph dependencies, not
packages compiled into SupiVPN or its tests. They are not promoted to explicit
requirements merely to suppress update output. Vulnerability checks inspect
the application and its tests.

Official Actions remain SHA-pinned: checkout 7.0.1, setup-go 7.0.0, cache 6.1.0,
upload-artifact 7.0.2, download-artifact 8.0.2, setup-buildx-action 4.4.1 and
build-push-action 7.4.0. Their Node 24 runtime is supported by the hosted runners.
Artifact uploads retain ZIP archives; downloads reject digest mismatches.
The existing attest 4.2.2 action was already current. Workflow permissions and
the separate tag/commit/artifact signing roles are preserved.

## Contributor workflow

`make setup` prepares project-local Python tools and downloads Go dependencies.
`make test` is the initial code-development check; documentation-only changes do
not need a product build. Hosted CI runs the full architecture matrix. Make
selects the host's ARM64/AMD64 architecture by default, with an explicit `ARCH`
override for cross-builds. `postgres-start` waits for its own newly created
container to become healthy, with a bounded timeout and no automatic cleanup of
pre-existing resources. The local Go module boundary is preserved.

## Validation

Release validation includes unit/race tests, vet, PostgreSQL integration,
XMLSec interoperability, SAML/XML fuzzing, real OpenVPN tests on ARM64 and AMD64,
module integrity, and source/binary vulnerability scans. Mock-Docker tests cover
readiness, failed creation, exited/missing/unhealthy containers and timeouts.
Tag checks must pass before the separate release workflow verifies provenance
and signs the checksum manifest. Known-vulnerability scans are point-in-time
results, not proof that dependencies contain no flaws.

## Upstream sources

- [Go release history](https://go.dev/doc/devel/release#go1.27.0).
- [AWS SDK changelog at v1.47.3](https://github.com/aws/aws-sdk-go-v2/blob/v1.47.3/CHANGELOG.md).
- [Smithy changelog at v1.28.5](https://github.com/aws/smithy-go/blob/v1.28.5/CHANGELOG.md).
- [OpenVPN 2.7.8 review](OPENVPN_UPGRADE.md).
- [PostgreSQL 18.6 release notes](https://www.postgresql.org/docs/release/18.6/).
- [GitHub Actions](https://github.com/actions) and [Docker Actions](https://github.com/docker).
