# Contributing to SupiVPN

SupiVPN is licensed under **AGPL-3.0-only**. Contributions are accepted under that
same license; contributors retain copyright in their work. See [COPYRIGHT.md](COPYRIGHT.md).
Discuss significant authentication, cryptography, database or recovery changes
in an issue before implementing them. Report suspected vulnerabilities privately
using [SECURITY.md](SECURITY.md).

## Local development

Use Go **1.27.2**, Python **3.11 or newer**, Git, Make and a C compiler for Go's
race detector. macOS on Apple Silicon is supported. Docker is optional for unit
tests and required for the disposable PostgreSQL, OpenVPN and XMLSec suites.
No cloud account, real IdP, deployment repository or production credential is required.

```bash
git clone https://github.com/SupiVPN/supivpn.git
cd supivpn
make prepare
```

`make prepare` audits sources, runs unit/race tests and vet, then builds Linux
ARM64 components. Build outputs are written to `local/arm64/`.
For a smaller feedback loop:

```bash
make test-saml
make test PKG=./internal/controller RUN=TestName
make vet
make build-all
```

For the full local integration checks, start Docker and use only the disposable
loopback database:

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
OpenVPN TUN tests; Docker supplies it on macOS. AMD64 remains supported, but its
local tests are slower when emulated on Apple Silicon. Hosted CI tests both
architectures natively. See [BUILD.md](BUILD.md) for security, fuzz and restart tests.

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

1. Fork the repository and create a focused branch.
2. Add tests for behavior or security boundaries that change. Preserve existing
   negative authentication and authorization tests.
3. Run the relevant checks and `make audit`. Write repository text in English.
4. Open a pull request targeting `main`, explaining the problem, behavior,
   validation and any operational or compatibility impact.
5. Wait for required checks and maintainer review. Respond to review with normal
   commits; do not assume CI success is security approval.

Public fork PRs use GitHub-hosted, disposable runners with no deployment or
publication credentials. A maintainer may need to approve a new contributor's
workflow run. Contributors do not need to enroll a GPG key in the release signer
policy. Maintainers sign releases; never put a signing private key into CI.

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
