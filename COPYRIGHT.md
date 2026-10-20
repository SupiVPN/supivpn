# Copyright and licensing

Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).

Stanislav Kazachkov is the copyright owner of the original SupiVPN software.
SupiVPN is his project and commercial designation; it is not a separate legal
entity. Publishing this project as open source does not transfer his copyright.
Contributors retain copyright in their own contributions.

The original code, tools, tests, migrations, examples and documentation in this
revision are licensed under the **GNU Affero General Public License, version 3
only** (`AGPL-3.0-only`). The complete, unmodified license is in [LICENSE](LICENSE).
There is no grant to choose a later license version. Files without individual
headers, including JSON examples and immutable SQL migrations, are included in
this grant unless they explicitly identify a different upstream license.

## Immutable SQL migrations

The original SQL migrations 001 through 009 in `internal/postgres/migrations/`
are expressly licensed under **AGPL-3.0-only** in this revision. This grant
supersedes their historical `LicenseRef-SupiVPN-Commercial` identifiers and
references to commercial licensing. Those headers are retained solely to
preserve the released SQL bytes and the checksums stored by existing databases;
they impose no additional restriction on these files in this revision.
[REUSE.toml](REUSE.toml) records this override for license tooling. The same grant
applies when these files are delivered as `migrations/*.sql` in a release bundle
or embedded in a SupiVPN binary.

## Third-party materials and earlier releases

Third-party materials retain their own copyrights and licenses. See
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) and
[THIRD_PARTY_LICENSES.txt](THIRD_PARTY_LICENSES.txt). In particular, OpenVPN is a
separate program under its upstream terms; this change does not relicense it.

Releases predating this grant retain their included licensing notices.

## Source availability

When conveying a binary, provide its exact Corresponding Source, including the
scripts needed to build and install it, under the terms of the AGPL. A link to a
moving default branch is not a substitute for the source of that binary.

If you modify SupiVPN and let users interact with that version over a network,
AGPL section 13 requires a prominent, no-charge opportunity to obtain that
version's Corresponding Source. Keep the source offer accessible to those users
and include your modifications. See [open-source distribution](docs/OPEN_SOURCE.md).

Commercial use is permitted under the AGPL. Sponsorship is optional and does not
change the license, impose connection limits, or grant an exception to copyleft.
No trademark rights are granted by this copyright notice.
