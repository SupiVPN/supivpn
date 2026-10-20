# Dependency upgrade for v0.1.1

Reviewed on 9 October 2026. This is a patch release: the database schema remains
at version 9 and the release bundle contract remains at version 3. No application
configuration migration is required.

## Updated components

| Component | Version | Review |
| --- | --- | --- |
| OpenVPN Community | 2.7.8 | Security fixes and integration assessment in [OPENVPN_UPGRADE.md](OPENVPN_UPGRADE.md). Installed separately from SupiVPN. |
| Release/CI Go toolchain | 1.27.2 | Security fixes in the Go command, TLS, HTTP, templates and OS packages; compiler/runtime fixes. |
| AWS SDK core | 1.47.2 | Updated SDK modules and Smithy dependency. |
| AWS config / credentials / IMDS | 1.33.8 / 1.20.8 / 1.20.2 | Stable dependency updates. |
| EC2 / Secrets Manager clients | 1.338.3 / 1.50.3 | API additions and dependency updates; existing recovery operations remain covered by tests. |
| Smithy | 1.28.4 | Includes the upstream revert of the trailing-slash JoinPath change and JSON error handling fixes. |
| etree | 1.8.1 | Prevents Remove calls from panicking when a token has no parent. |
| puddle | 2.2.3 | Fixes asynchronous pool construction during close/reset and semaphore acquisition. |
| Disposable PostgreSQL / CI base | 18.6 | Stable PostgreSQL 18 security and correctness fixes. The production database is managed separately. |

Eighteen of the 25 declared Go modules changed, including AWS transitive modules.
The complete versions and retained license texts are in
[THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md) and
[THIRD_PARTY_LICENSES.txt](../THIRD_PARTY_LICENSES.txt). All 32 retained upstream
license/notice files were compared with the new module cache; their text is
unchanged.

`pgx/v5` 5.11.0, `aws-lambda-go` 1.55.1, the declared `golang.org/x` modules and
`govulncheck` 1.8.0 were already current. No declared module is retracted.
The full module graph also lists newer versions of `kr/pretty`, `objx`,
`testify` and `x/tools`. These are upstream test/unused graph dependencies, not
packages compiled into SupiVPN or its tests; they are not promoted to explicit
requirements merely to suppress update output. `go mod why -m` identifies
`testify` through the AWS Lambda module's own tests, which this project does not
run. Vulnerability checks still inspect the application and its tests.

Make and CI create a `local/go.mod` boundary before Go commands so
recursive discovery cannot treat downloaded, older non-module dependencies as
SupiVPN source.

## Validation

Release validation includes unit/race and security tests, vet, PostgreSQL 18.6
integration, XMLSec interoperability, SAML/XML fuzzing, real OpenVPN tests on
ARM64 and AMD64, module integrity checks, and source/binary vulnerability scans.
CI repeats the release gates using digest-pinned images. Known-vulnerability
checks are a point-in-time result, not proof that dependencies contain no flaws.

## Upstream sources

- [Go release history](https://go.dev/doc/devel/release#go1.27.0).
- [AWS SDK changelog at v1.47.2](https://github.com/aws/aws-sdk-go-v2/blob/v1.47.2/CHANGELOG.md).
- [Smithy changelog at v1.28.4](https://github.com/aws/smithy-go/blob/v1.28.4/CHANGELOG.md).
- [etree v1.8.1](https://github.com/beevik/etree/releases/tag/v1.8.1).
- [puddle v2.2.3](https://github.com/jackc/puddle/releases/tag/v2.2.3).
- [PostgreSQL 18.6 release notes](https://www.postgresql.org/docs/release/18.6/).
