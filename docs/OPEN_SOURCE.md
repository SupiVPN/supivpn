# Open-source distribution

Original SupiVPN code is licensed under AGPL-3.0-only. Copyright remains with
Stanislav Kazachkov and the authors of their respective contributions.
See [COPYRIGHT.md](../COPYRIGHT.md) and the complete [LICENSE](../LICENSE).

## Binary releases

Each binary release must have Corresponding Source for that exact version,
including its build scripts and dependency source required by the license.
The release workflow publishes a source archive beside the Linux bundles.
A link to the moving main branch is not a source offer for a particular binary.

The source archive contains the signed revision's files, vendored Go modules,
toolchain notices and a checksum inventory. Build with the documented Go
version, for example `GOFLAGS=-mod=vendor make build ARCH=arm64`.
The Go toolchain and optional interoperability-test tools are installed separately.

OpenVPN is a separate upstream program, distributed under its own license.
If you distribute it alongside SupiVPN, satisfy its upstream source and notice
requirements as well. The SupiVPN bundles contain no OpenVPN executable.
Third-party terms remain in [THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md)
and [THIRD_PARTY_LICENSES.txt](../THIRD_PARTY_LICENSES.txt).

## Modified network services

AGPL section 13 requires a modified network version to prominently offer its
Corresponding Source to all users interacting with it remotely, without charge.
Include your modifications and the scripts needed to build and install them.
Provide a working link in the user-facing portal or service interface; retaining
source only in an administrator-only location is insufficient.

The application currently has no configurable source-offer banner or source
hosting endpoint. Operators of modified versions must provide that opportunity
as part of their user-facing service.

Commercial use and charging for hosting or support are allowed under the AGPL.
Sponsorship is voluntary and does not change recipients' license rights.
For the exact obligations, read the [AGPL text](https://www.gnu.org/licenses/agpl-3.0.html).
