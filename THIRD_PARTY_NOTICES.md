# SupiVPN licensing and third-party notices

Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
Original SupiVPN materials: AGPL-3.0-only. See [LICENSE](LICENSE) and [COPYRIGHT.md](COPYRIGHT.md).

This document distinguishes original SupiVPN materials from third-party
components. Third-party copyrights and license texts remain with their owners.
Dependency inventory and packaging reviewed on 20 October 2026 against
`go.mod`, the retained license texts and the current packaging code.

## Original SupiVPN materials

[LICENSE](LICENSE) applies to original SupiVPN materials distributed with it,
including code, tools, migrations, tests, examples, documentation and original
portions of binaries. File-level headers are not required to establish this
scope. Independent deployment repositories and operator configuration are
not brought under this license merely by using SupiVPN.

Third-party code, downloaded dependencies, IdP metadata and system packages
retain their own terms. JSON examples and original SQL migrations are covered
without inserting comments into JSON or changing migration checksums.

The original SQL migrations 001 through 009, delivered as `migrations/*.sql`
and embedded in SupiVPN binaries, are expressly licensed under **AGPL-3.0-only**
in this distribution. This grant supersedes the historical
`LicenseRef-SupiVPN-Commercial` identifiers and commercial-license references
retained in their headers. Those headers preserve released SQL checksums and
impose no additional restriction on these files in this distribution.
The source tree records the same override in `REUSE.toml`.

## OpenVPN Community 2.7.8

OpenVPN Community is a separate third-party VPN daemon, copyright OpenVPN Inc
and other contributors, under GPL version 2 with the exceptions and
component-specific terms supplied by its upstream distribution.

Current integration:

- Deployment installs OpenVPN as a separate operating-system package or daemon.
- The Go agent uses the documented management protocol over a Unix socket and
  an external `learn-address` command. It does not link OpenVPN into its binary.
- The profile CLI invokes OpenVPN's native `--genkey` commands. HTTPS profile
  issuance uses the original Go implementation of the tls-crypt-v2 wire format.
- The SupiVPN source tree contains no vendored OpenVPN source or binary.
  The release archive and Lambda ZIP contain SupiVPN executables and their
  compiled Go dependencies, not the OpenVPN daemon.
- The separate CI image defined by `ci/Dockerfile` builds and installs OpenVPN
  2.7.8 from an upstream archive with a pinned SHA-256, recorded after verifying
  the upstream detached OpenPGP signature.
  An image built from this recipe contains OpenVPN and other system packages;
  its distribution has separate obligations described below.

This separation supports treating the original SupiVPN programs as independent
works. A socket/process boundary alone is not a legal guarantee: copying
OpenVPN code, linking it, writing an in-process plugin, or materially changing
the integration requires a fresh copyleft review. The OpenSSL and Apache-2.0
linking exceptions do not change the license of OpenVPN itself.

Sources:

- [OpenVPN COPYING, release v2.7.8](https://github.com/OpenVPN/openvpn/blob/v2.7.8/COPYING).
- [OpenVPN management interface](https://openvpn.net/community-docs/management-interface.html).
- [GPLv2 terms, especially sections 1, 2, 3 and 6](https://www.gnu.org/licenses/old-licenses/gpl-2.0.html).
- [FSF guidance on separate programs and aggregation](https://www.gnu.org/licenses/old-licenses/gpl-2.0-faq.html#MereAggregation).

## Distribution of OpenVPN or an image containing it

Operating a server or installing packages from the distribution repository
does not itself mean that SupiVPN is distributing an OpenVPN binary.
Internal use does not by itself require public release of source code.

If an installer, VM image, container, appliance or other delivery includes an
OpenVPN binary supplied by us, even an unmodified one:

1. Retain the upstream copyright notices, GPL text, applicable exceptions and
   notices for the exact supplied build and its bundled components.
2. Meet GPLv2 section 3 for that exact binary. Prefer accompanying it with the
   complete corresponding source, including distribution patches, interface
   definitions and build/installation scripts as required by the GPL.
3. If using a written source offer instead, it must satisfy section 3(b):
   valid for at least three years, available to any third party, at no more
   than the cost of physically distributing source. A generic upstream link
   or another vendor's offer is not a substitute for our own compliance;
   section 3(c)'s pass-through option is limited to noncommercial distribution.
4. Mark distributed OpenVPN modifications and their dates as required; keep
   GPL-covered code under its applicable terms. Proprietary terms, an NDA or
   license fees must not restrict recipients' GPL rights.

This document is not itself a written source offer. Verify the exact binary,
source archive, patches, linked libraries and notices for each supplied build.
The CI Dockerfile currently removes its downloaded OpenVPN archive and build
tree. It does not produce a corresponding-source delivery or a written offer.
Before distributing that image, prepare the required license and source
materials for OpenVPN and the other included components. A Dockerfile, source
URL or archive checksum alone does not fulfill these obligations.

## Go dependencies

The following inventory covers all 25 dependencies declared in `go.mod`,
including indirect dependencies. Versions match the retained upstream license
texts in `THIRD_PARTY_LICENSES.txt`. It is a module-level inventory,
not an artifact-specific SBOM or an inventory of every module in the download
cache. Different executables may compile different subsets of these modules.

| Module | Version | Upstream license |
| --- | --- | --- |
| `github.com/aws/aws-lambda-go` | `v1.55.1` | Apache-2.0; MIT-0 for material identified by LICENSE-SUMMARY |
| `github.com/aws/aws-sdk-go-v2` | `v1.47.3` | Apache-2.0 |
| `github.com/aws/aws-sdk-go-v2/config` | `v1.33.9` | Apache-2.0 |
| `github.com/aws/aws-sdk-go-v2/credentials` | `v1.20.9` | Apache-2.0 |
| `github.com/aws/aws-sdk-go-v2/feature/ec2/imds` | `v1.20.3` | Apache-2.0 |
| `github.com/aws/aws-sdk-go-v2/service/ec2` | `v1.339.0` | Apache-2.0 |
| `github.com/aws/aws-sdk-go-v2/service/secretsmanager` | `v1.50.5` | Apache-2.0 |
| `github.com/beevik/etree` | `v1.8.1` | BSD-2-Clause |
| `github.com/jackc/pgx/v5` | `v5.11.0` | MIT |
| `golang.org/x/sys` | `v0.49.0` | BSD-3-Clause |
| `github.com/aws/aws-sdk-go-v2/internal/configsources` | `v1.5.6` | Apache-2.0 |
| `github.com/aws/aws-sdk-go-v2/internal/endpoints/v2` | `v2.8.6` | Apache-2.0 |
| `github.com/aws/aws-sdk-go-v2/internal/v4a` | `v1.5.6` | Apache-2.0 |
| `github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding` | `v1.13.21` | Apache-2.0 |
| `github.com/aws/aws-sdk-go-v2/service/internal/presigned-url` | `v1.14.6` | Apache-2.0 |
| `github.com/aws/aws-sdk-go-v2/service/signin` | `v1.10.4` | Apache-2.0 |
| `github.com/aws/aws-sdk-go-v2/service/sso` | `v1.38.4` | Apache-2.0 |
| `github.com/aws/aws-sdk-go-v2/service/ssooidc` | `v1.43.4` | Apache-2.0 |
| `github.com/aws/aws-sdk-go-v2/service/sts` | `v1.51.4` | Apache-2.0 |
| `github.com/aws/smithy-go` | `v1.28.5` | Apache-2.0 |
| `github.com/jackc/pgpassfile` | `v1.0.0` | MIT |
| `github.com/jackc/pgservicefile` | `v0.0.0-20240606120523-5a60cdf6a761` | MIT |
| `github.com/jackc/puddle/v2` | `v2.2.3` | MIT |
| `golang.org/x/sync` | `v0.24.0` | BSD-3-Clause |
| `golang.org/x/text` | `v0.43.0` | BSD-3-Clause |

AWS SDK and Smithy also contain Go-derived subcomponents under BSD terms.
The AWS Lambda module's own LICENSE-SUMMARY distinguishes its Apache-2.0 code
from material under MIT No Attribution. Those notices are preserved rather
than applying one license to all upstream files.

[THIRD_PARTY_LICENSES.txt](THIRD_PARTY_LICENSES.txt) contains the
full module LICENSE texts and discovered NOTICE files for these versions,
including the nested AWS BSD notices. Identical texts are stored once with all
their source paths listed. It does not relicense these components.

## Build, test and deployment components

The Go runtime and standard library are compiled into the executables.
`THIRD_PARTY_LICENSES.txt` includes the Go 1.27.3 LICENSE/PATENTS and discovered
source-tree LICENSE, NOTICE and COPYING texts, with their upstream paths.
This conservative inventory includes toolchain components beyond those compiled
into a particular executable. Recheck it when changing the build toolchain.

The CI image also includes PostgreSQL, Python and PyYAML, XMLSec, OpenSSL,
compression libraries, Git, GnuPG, compiler tools and operating-system packages.
These are build/test components, not additional entries in `go.mod`.
The CI image's package inventory depends on its selected base image digests and
installed package versions. Its complete notices and corresponding-source
materials, where required, are not generated by the SupiVPN release bundler.

Docker is a separately installed test tool.
Deployment components such as dnsmasq, nftables, Terraform providers and shared
modules also retain their own licenses. They are not included in the SupiVPN
release archive. Review their exact versions and notices if supplying them in
an image, appliance or other combined delivery.

OpenVPN Connect is separately licensed client software; this license does not
grant redistribution rights for it.

## Release materials

The versioned archive produced by `tools/artifacts.py` automatically
includes these files and records their checksums in `bundle.json`:

- `LICENSE`;
- `THIRD_PARTY_NOTICES.md`;
- `THIRD_PARTY_LICENSES.txt`.

See [RELEASES.md](docs/RELEASES.md) for the complete archive contract and download
checks. OpenVPN is installed separately. Hash verification checks
integrity; it does not establish that every required license notice is present.

The public Lambda ZIP contains `bootstrap` and `client.ovpn.template`; the agent
and recovery ZIPs contain their respective `bootstrap`. The license documents
accompany all three in the outer archive.
The standalone Lambda packager does not embed legal documents. When delivering
a ZIP, individual executable or source package separately, provide the
applicable license documents with that delivery as well.

Before an external release, check actual binary dependencies and the exact Go
toolchain (including bundled code under separate notices), retain applicable
copyright and NOTICE entries, and update this inventory after dependency
changes. Include GPL source materials when distributing OpenVPN or other
GPL-covered system packages.

The AGPL grant covers original SupiVPN materials, not ownership of third-party
code. Supply the exact Corresponding Source alongside public SupiVPN binaries
and preserve the dependency notices. The current product archive excludes the
OpenVPN daemon; do not publish a CI/container image as if it were covered only
by the SupiVPN license.
