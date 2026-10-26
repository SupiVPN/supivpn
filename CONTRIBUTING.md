# Contributing to SupiVPN

SupiVPN is licensed under **AGPL-3.0-only**. Contributions are accepted under that
same license; contributors retain copyright in their work. See [COPYRIGHT.md](COPYRIGHT.md).
Discuss significant authentication, cryptography, database or recovery changes
in an issue before implementing them. Report suspected vulnerabilities privately
using [SECURITY.md](SECURITY.md).

## Local development

Use Go **1.27.3 or newer**, Python **3.11 or newer**, Git, Make and a C compiler for Go's
race detector. macOS on Apple Silicon is supported. Docker is optional for unit
tests and required for the disposable PostgreSQL, OpenVPN and XMLSec suites.
No cloud account, real IdP, deployment repository or production credential is required.
The minimum Go version lives in `go.mod`; CI reads that file too. Select another
installed SDK with `make GO=/path/to/go test` or your IDE's project SDK setting.

For documentation-only changes, edit the Markdown and open a PR; there is no
need to install Go or Docker or build the product. Check the rendered text and
links; hosted CI runs the applicable documentation checks on both PRs and pushes
to `main`. Only root-level and `docs/` Markdown qualifies; copyright/notices,
source, dependencies, packaging and CI changes keep the full checks. Release
tags, scheduled and manual runs always run the full suite, as does an unknown
or unavailable diff. See [CI selection and CodeQL setup](docs/CI.md).

For code changes, fork the repository on GitHub and clone your fork (replace
`YOUR-USERNAME` below):

```bash
git clone https://github.com/YOUR-USERNAME/supivpn.git
cd supivpn
git switch -c fix/short-description
make setup
make test
```

`make setup` downloads Go modules and installs PyYAML 6.0.3 in the ignored
`local/dev-venv/`. Make uses that environment automatically; shell activation
and global Python-package installation are unnecessary. It does not install
Go, Docker or GnuPG. Re-run it after dependency updates.

Run the tests relevant to your change while developing:

```bash
make test-saml
make test PKG=./internal/controller RUN=TestName
make vet
make audit
```

The full ARM64/AMD64 matrix runs in hosted CI. A small change does not require
running every integration, fuzz and cross-build locally. `make prepare` remains
available for a complete local audit, unit/race, vet and Linux build.

`make audit` prints individual skipped tests and their reasons. Workflow tests
need PyYAML; disposable signing tests also need `gpg` and `gpgconf` on PATH.
They generate their own temporary keys and never need your working signing key.
The built-bundle test is intentionally opt-in; see [BUILD.md](BUILD.md).

For database, XML signature or OpenVPN changes, run the relevant integration
suite with Docker. PostgreSQL uses only a disposable loopback database:

```bash
make postgres-start
export SUPIVPN_TEST_POSTGRES_URL='postgres://postgres@127.0.0.1:55432/supivpn_test?sslmode=disable'
export SUPIVPN_TEST_POSTGRES_ALLOW_RESET=1
make integration
make postgres-stop
make test-xmlsec
make openvpn-image test-openvpn
```

Never use an operational database for tests. `trust` authentication above applies
only to the temporary, loopback-published test container. Linux is required for
OpenVPN TUN tests; Docker supplies it on macOS. Make defaults to the host's
ARM64 or AMD64 architecture. Use `ARCH=arm64` or `ARCH=amd64` for an explicit
cross-build; emulation may be slower. `postgres-start` waits for readiness or
fails within its configured timeout. See [BUILD.md](BUILD.md) for additional checks.

## IDE setup

Open the repository root containing `go.mod` in GoLand or another Go-aware IDE.
There is one module and no `go.work`. Set `GOWORK=off`, `GOTOOLCHAIN=local`,
`GOPATH=$PROJECT_DIR$/local/go` and `GOCACHE=$PROJECT_DIR$/local/build-cache`.
Exclude `local/` and `out/` from indexing. Run `make deps-verify` once so the
`local/go.mod` boundary exists before recursive IDE discovery.

For recursive GoLand tests use **Go Test / Directory**, repository root,
Go arguments `-race -count=1`. For SAML alone use package
`supivpn/internal/saml`. Integration configurations add `-tags=integration` and
the disposable database environment above.

## Pull requests

1. Fork the repository and create a focused branch from `main`. Any descriptive
   name is welcome; `fix/`, `feat/`, `docs/` and `ci/` are optional conventions.
2. Add tests for behavior or security boundaries that change. Preserve existing
   negative authentication and authorization tests.
3. Run the relevant checks and `make audit` for code/tooling changes. Write
   repository text in English. Describe any checks you could not run locally.
4. Open a pull request targeting `main`, explaining the problem, behavior,
   validation and any operational or compatibility impact.
5. Wait for required checks and maintainer review. Respond to review with normal
   commits; do not assume CI success is security approval.

Public fork PRs use GitHub-hosted, disposable runners with no deployment or
publication credentials. The repository currently requires maintainer approval
for workflow runs from all external contributors, including returning authors.
If checks show "Awaiting approval", the maintainer handles that step; you do
not need to set up runners, secrets or a second CI system.

Commit signing is optional for contributions. Maintainers sign release tags and
artifacts using the separate release policy; contributors do not enroll release
keys. There is no required commit-message format, CLA or DCO sign-off.
Small fixes and documentation improvements can go straight to a PR. Discuss
the significant security or architectural changes listed above before coding.

Applied SQL migrations are immutable. Prefer additive, backward-compatible
changes and test old/new runtime compatibility before declaring a rolling
upgrade safe. See [the migration policy](docs/POSTGRES.md#migration-authoring-policy).

New original source files use:

```text
Copyright (c) YEAR AUTHOR.
Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
SPDX-License-Identifier: AGPL-3.0-only
```

Use the comment syntax appropriate to the file. Preserve existing authors and
third-party notices. Do not claim somebody else's contribution as your own.
