# Building and testing SupiVPN

Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
See [LICENSE](LICENSE) for copyright ownership and licensing terms.

Run `make <target>` from the SupiVPN root, or `make -C /path/to/supivpn <target>`.
Requirements: GNU Make, the Go version in `go.mod` (currently 1.27.3) or newer Go,
and a C compiler for the race detector.
Docker is required only for PostgreSQL/XMLSec/OpenVPN. `make help` lists all targets.
For a first contribution, follow [CONTRIBUTING.md](CONTRIBUTING.md): `make setup`
installs the Python audit dependency in `local/dev-venv/` and downloads Go modules,
then `make test` runs unit/race tests. A full release build is not required to
make a small code or documentation change.

## Build

| Command | Artifact in `local/<arch>/` |
| --- | --- |
| `make build` or `make all` | All artifacts below |
| `make agent` | `supivpn` |
| `make controller` | `supivpn-controller` HTTP service |
| `make profile` | `supivpn-profile` profile utility |
| `make migrate` | `supivpn-migrate` |
| `make lambda` | Public, agent and recovery bootstraps plus three Lambda ZIPs |

Deployment binaries target **Linux, CGO=0**, using the host's ARM64 or AMD64
architecture by default. Use `ARCH=arm64` or `ARCH=amd64` to select explicitly,
or `make build-all` for both. Outputs are
separate under `local/arm64/` and `local/amd64/`; a partial build cannot silently
overwrite the other architecture. The packager validates the requested ELF machine.
The public ZIP contains bootstrap and the profile template; the agent/recovery
ZIPs contain only their own bootstrap. The build does not package deployment metadata,
certificates or keys. See [component contracts](docs/LAMBDA_ISOLATION.md). Go caches and tools are stored in `local/`.
With `GOTOOLCHAIN=local`, the operator installs Go; Make does not download it automatically.
Building does not deploy or publish artifacts.

Prebuilt bundles are public GitHub Release assets; downloading them needs no
product checkout or token. Select an explicit release and architecture, then
check its SHA-256 before extraction. See [download instructions](docs/RELEASES.md#download)
for filenames, verification limits and the bundle contract.

`make tag VERSION=v0.4.0` fetches main and creates/verifies a local GPG-signed
tag. Optional `COMMIT=<full-SHA>` selects a specific main commit. Notes are
generated from Git log and embedded in the tag. The command never pushes or
publishes. See [release creation](docs/RELEASES.md#create-a-release).

[CI](ci/README.md) runs native ARM64 and AMD64 jobs on GitHub-hosted runners.
PostgreSQL and XMLSec are enabled for one race-enabled integration run including
unit tests, security regressions and fuzz seeds. `make ci-test-coverage` verifies
that integration tags retain the ordinary test suite. Each architecture also
runs real OpenVPN interoperability tests in an isolated container.
Tests, builds, OpenVPN, source security and both fuzz targets are independent
jobs. `Required checks` waits for all of them. Signed version tags run the
complete suite and produce their own release candidates.
Local Make targets remain independently usable. Audit tooling tests use Python;
workflow validation also requires PyYAML. `make setup` installs its pinned
version in a project-local virtual environment, which Make selects automatically.
`make audit` lists skip reasons: GPG tests need `gpg` and `gpgconf` on PATH but
generate disposable keys, and the built-bundle test requires the existing
`SUPIVPN_TEST_BUILT_BUNDLE=1` opt-in. A skipped check is not a passing check.

Before a release, run `make prepare`: source audit -> unit/race -> vet -> full build.
`make build` also creates `local/<arch>/release.json` with SHA-256 hashes of all
components and compatible VM SQL digests for schemas 7/8/9/10/11. Isolated Lambda
components explicitly require schema 11 in `lambda_components`. Profile ownership
and Server URL also require schema 11 on a VM. Building one component
does not update this contract: repeat prepare/build before a full deployment. CI runs `make security-binaries` on each native architecture;
both jobs must pass before a release candidate can be used.
Prefer compatible migrations; new online migrations require an explicit
compatibility review and integration tests. Follow the
[migration authoring policy](docs/POSTGRES.md#migration-authoring-policy).

## Test suites

### Debian packages

`make deb ARCH=arm64` or `ARCH=amd64` builds `supivpn-node`,
`supivpn-controller`, `supivpn` and matching vendored source in a disposable
Debian 13 builder. `make deb-test` additionally checks package contents, unit
syntax and the package installation/removal lifecycle. Outputs stay under
`local/debian/<arch>/`; nothing is installed on the development host.
`make deb-vm-test ARCH=arm64` (or `amd64`) additionally boots an isolated Debian
VM and checks real systemd lifecycle, signed SAML login, VPN traffic, dependency
outages, session expiry/reconnect, and the two-port profile migration (owner,
cross-port refusal, block/reactivate and Server URL protocol). Reboot and live
package upgrades cover both installed node/OpenVPN pairs. It uses
software CPU emulation and needs Internet access for guest prerequisites; VM
disks and evidence stay in `local/debian-vm/`.
See [Debian packaging](docs/DEBIAN_PACKAGING.md) for prerequisites and the
distinction between container checks and clean-VM acceptance.
Native Connect Server URL acceptance uses the separate
[interactive fixture](docs/CONNECT_TEST.md#server-url-import); VM HTTP tests
do not substitute for importing through the client UI.

| Command | Checks |
| --- | --- |
| `make audit` | Local pre-commit file, secret-pattern, and repository language checks plus auditor tests; no Git or network access |
| `make test` | Unit tests with the race detector; integrations requiring external tools are skipped |
| `make test-saml` | SAML and controller unit/race tests |
| `make test-security` | Attacks on SAML signatures and login binding, IdP keys, agent API, node decisions, and profiles; race detector, no Docker |
| `make vet` | `go vet`, including integration code |
| `make integration` | PostgreSQL 18 migrations, roles, TLS, reconnect, replay, remote controller, profiles, and clustering |
| `make test-xmlsec` | Independent XML signature checks using XMLSec in Docker |
| `make test-openvpn` | Real OpenVPN 2.7.8: foreground/daemon startup, tls-crypt-v2, SAML, IP pools, and two-node failover |
| `make test-connect` | Interactive OpenVPN Connect on Mac: expiry, automatic reconnect, and a new browser login; [instructions](docs/CONNECT_TEST.md) |
| `make fuzz` | Two 20-second runs: XML/C14N and signed SAML mutations; `FUZZ_TIME=60s` sets the duration of **each** |
| `make fuzz-xml` / `make fuzz-saml` | Parser/C14N only, or preservation of verified claims under signed SAML mutations |
| `make security` | `test-security` plus govulncheck for the current platform, Linux, test code, and all deployment binaries |
| `make deps-check` | Module integrity, available updates, retractions, and the latest govulncheck version |
| `make check` | `test vet security deps-check`, without Docker |
| `make test-all` | Sequential `check integration test-xmlsec test-openvpn fuzz` |

Fencing, maintenance, and blocked recovery are covered by `make integration`.
To run only these tests:
`make integration RUN='TestFencingRegression|TestOperatorRecovery|TestAutomaticRecovery|TestSessionLimits'`.
Use the same disposable local PostgreSQL database and reset opt-in.
No additional Go build tag is required for these checks; PASS verifies the regression guarantees.

Selecting specific tests:

```bash
make test PKG=./internal/controller RUN='TestProfile'
make test RUN='TestOperator|TestSubjectHash|TestRejectMalformedSubjectHash'
make integration PKG=./internal/agent RUN='TestOperatorDropUserIntegration'
make integration PKG=./internal/agent RUN='TestPostgresReconnect'
make test vet security
make test-security
make fuzz-saml FUZZ_TIME=60s
```

`PKG`, `RUN`, and `TIMEOUT` apply to `test` and `integration`.
Defaults: all packages/tests, 300s timeout. Do not set filters for a complete run.
`TEST_VERBOSE=-v` enables detailed integration output.
Make runs targets sequentially even with `-j` to prevent concurrent resets or
restarts of the shared test database. Do not run integration suites concurrently
in separate terminals.

`test-security` ignores `PKG`/`RUN` so a previous filter cannot skip checks.
It runs every unit/race test in the Go module, including adversarial scenarios,
VM/AWS adapters, the allocator, and the packager.
PostgreSQL replay and cross-controller concurrency are covered by `integration`;
XMLSec and OpenVPN remain separate targets included in `test-all`.

Fuzzing uses synthetic data and newly generated temporary keys, never deployment
metadata. Beyond checking for panics, it verifies stable canonical bytes after
reparsing and preservation of every verified claim in accepted signed-response
mutations, including the user, groups, and validity periods.
Save any Go fuzzing counterexample as a regression test before fixing it.
Main CI uses iteration budgets: 500,000 XML/C14N and 100,000 signed-claim executions;
scheduled CI uses 5,000,000 and 1,000,000 respectively. Each target still has a
600-second hard timeout. Any test failure or timeout fails CI; no retry or error
suppression is used. This avoids the short fuzz-duration shutdown race reported in
[Go issue 75804](https://github.com/golang/go/issues/75804).
Reproduce with `make fuzz FUZZ_TIME=500000x FUZZ_SAML_TIME=100000x TIMEOUT=600s`.

## Local PostgreSQL for integration

```bash
make postgres-start
export SUPIVPN_TEST_POSTGRES_URL='postgres://postgres@127.0.0.1:55432/supivpn_test?sslmode=disable'
export SUPIVPN_TEST_POSTGRES_ALLOW_RESET=1
make integration
make postgres-stop
```

This is a disposable **supivpn_test** database, available over loopback without a
password. Tests reject RDS, non-loopback addresses, and other database names.
`postgres-start` waits up to 60 seconds for its new container's health check
before succeeding. Override `POSTGRES_WAIT_TIMEOUT` if needed. Unhealthy,
stopped or missing containers and readiness timeouts fail the command. Creation
failure never causes it to reuse an existing container; readiness failure leaves
the new container available for inspection and `make postgres-stop` cleanup.
`sslmode=disable` applies only to this disposable backend; TLS/reconnect tests
create their own TLS endpoint. Deployment connections continue to use TLS.

`postgres-stop` accepts only a container bearing the test label. Docker removes
the container and its anonymous volume after stopping it. Override
`POSTGRES_CONTAINER`, `POSTGRES_PORT`, or `POSTGRES_IMAGE` as needed; update the
test URL when changing the port. The default is `postgres:18.6-bookworm`, pinned
by digest in the Makefile; review and refresh that digest with dependency updates.

A separate **interactive** test covers a real PostgreSQL restart:

1. Run `make test-db-restart` with the same test database and variables.
2. After `READY_FOR_LOCAL_DB_RESTART`, run `docker restart supivpn-pg18-test`
   in another terminal.
3. Wait for PASS, then run `make postgres-stop`.

This test requires a synchronized external restart and is not part of `test-all`.
Automated interruption, timeout, and DNS re-resolution tests are part of `integration`.

## Docker suites

`make test-xmlsec` builds its local image from
[testdata/saml/Dockerfile](testdata/saml/Dockerfile).
Signatures are checked in both directions: SupiVPN -> XMLSec and XMLSec -> SupiVPN,
for Response, Assertion, and Exclusive C14N with InclusiveNamespaces.
Additional fixtures cover default namespaces, prefix overrides, comments/text,
and attribute escaping. Changing the user or group after XMLSec signing must fail.

Prepare the OpenVPN image once:

```bash
make openvpn-image
make test-openvpn
```

The checked-in `ci/Dockerfile` builds OpenVPN **2.7.8** from a checksum-pinned
upstream archive. No private installer or deployment repository is required.
See [native tests](testdata/openvpn/README.md).
Use `OPENVPN_IMAGE` to select an existing image matching `ARCH`. Docker suites
also use the host architecture; set `ARCH=arm64` or `ARCH=amd64` explicitly for cross-testing.
Test containers have no network; OpenVPN receives TUN/NET_ADMIN only inside the
container. Tests generate temporary keys and a synthetic IdP.

Startup checks the management handshake and readiness after `state on` /
`hold release`. OpenVPN 2.7.8 acknowledges `version 5` separately; receive that
ACK before sending the next command. A unit test ensures the ACK cannot mask
a subsequent command failure. Raw management transcripts are never printed.

The TLS-crypt-v2 suite keeps the profile's `hand-window 180` for valid keys.
Only missing, foreign, and tampered keys use five seconds to bound silent
rejection. OpenVPN also uses this window to detect server silence during
`AUTH_PENDING`; five seconds can race a `PUSH_REQUEST` retry under emulation.
A seven-second SAML delay must neither establish an unauthorized tunnel nor
restart the client, and must still finish with the expected group address.
Protocol-marker waits remain bounded at 12 seconds; no failure retries are used.
Failure diagnostics include fixed restart categories, never raw auth URLs.

For the full automated suite, start test PostgreSQL, export the two variables,
prepare the OpenVPN image, run **`make test-all`**, then stop PostgreSQL.
Live Okta/OpenVPN Connect login and cloud load balancer behavior require separate
deployment acceptance tests.

## Dependency updates and vulnerabilities

Run `make security deps-check` before every release and at least weekly.
Review **all** direct and transitive dependencies, AWS SDK, the Go toolchain,
OpenVPN, and base-image packages. `deps-check` also lists test/tool modules in
the graph; presence in that graph does not imply inclusion in a binary.

The Makefile pins `govulncheck` (`v1.9.0`); its vulnerability database is refreshed
during checks. Source analysis runs locally; modules and the
[Go vulnerability database](https://go.dev/doc/security/vuln/) are downloaded.
`deps-check` changes nothing. For accepted updates, review changelogs, update
`go.mod/go.sum` and third-party notices, then repeat builds and checks.

The Checks workflow runs source vulnerability scans and bounded fuzzing on code
changes. Its weekly schedule also checks dependency freshness and runs extended
fuzzing. A successful govulncheck means no known issues were found,
not that the custom SAML implementation has been independently audited.

## GoLand

Open the repository root containing `go.mod` and enable Go modules integration.
Use a supported Go SDK, `GOWORK=off`, `GOTOOLCHAIN=local`,
`GOPATH=$PROJECT_DIR$/local/go` and `GOCACHE=$PROJECT_DIR$/local/build-cache`.
Exclude `local/` and `out/` from indexing.

Make creates a `local/go.mod` module boundary before Go commands. Keep
it in place: recursive package discovery must not inspect downloaded modules or
generated source under `local/`. Run `make deps-verify` once before invoking Go
commands directly in a fresh checkout.

For recursive unit/race tests, select **Go Test -> Test kind: Directory**,
directory and working directory `$PROJECT_DIR$`, Go tool arguments
`-race -count=1`, and program arguments `-test.timeout=300s`.
Do not use `supivpn/...` with the Package kind.

For SAML tests, use **Package** `supivpn/internal/saml` with the same working
directory and arguments. For integration tests, use the Directory configuration,
add `-tags=integration` and the disposable local PostgreSQL environment from
the integration section above. Never point it at an operational database.
To build the agent, select package `supivpn/cmd/supivpn`; the other command
packages retain their names.

### OpenVPN 3 Linux interoperability

`make openvpn-image linux-client-image test-linux-client` runs the official
OpenVPN 3 Linux client in a disposable network namespace against unmodified
OpenVPN, signed synthetic SAML, inline profile credentials and disjoint format
gates. It creates only a synthetic container machine ID. No desktop installation
or real IdP credentials are required. The Linux importer uses downloaded `.ovpn`
files; Server URL acceptance in OpenVPN Connect is a separate UI check.
