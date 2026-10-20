# Release delivery

SupiVPN publishes Linux ARM64 and AMD64 bundles and Corresponding Source on
[GitHub Releases](https://github.com/SupiVPN/supivpn/releases). ARM64 is the default.

## Create a release

Select a reviewed commit on main. From a clean checkout with your authorized
OpenPGP tag-signing key configured:

```bash
make tag VERSION=v0.4.0
git push origin refs/tags/v0.4.0
```

The example version must be replaced with the next unused version. `make tag`
fetches main, selects its exact SHA and generates notes from commit subjects.
Use `COMMIT=<full-SHA>` to select an earlier main commit. It verifies the local
signed tag and prints the explicit push command; it never pushes.

Pushing the tag starts **Checks** for that tag's exact commit. Native ARM64 and
AMD64 tests and builds run in parallel with source audit, security checks and
fuzzing. Wait for the entire tag workflow, including `Required checks`, to
succeed. Then start publication from the protected main branch:

```bash
gh workflow run release.yml --repo SupiVPN/supivpn --ref main -f tag=v0.4.0
```

The main workflow supplies the trusted release tooling; the binaries and source
come from the successful tag run. A newer main commit cannot replace the tagged
source. Main and PR runs do not supply release candidates.

Use semantic versions: patch for compatible fixes or dependency updates, minor
for features, and major for incompatible stable API changes. During 0.x,
document all breaking changes explicitly. Prereleases use `-alpha.N`,
`-beta.N` or `-rc.N`. Promote an RC by signing a stable tag at the same SHA
when no source change is needed.

Review and approve the `release` environment after preparation succeeds.
The signing job creates a detached OpenPGP signature over `SHA256SUMS`, covering
both binary bundles, Corresponding Source and release notes. The publication job
independently verifies the signature using the pinned primary and artifact subkey.
The workflow uses exact successful tag candidates retained for seven days.
It verifies the signed tag object and version, source commit, run/attempt,
archive digest, schema and architecture. Publication does not rebuild or
repackage the archives and cannot fall back to main or another tag.
If candidates expired, rerun **all jobs** of the original tag push run, then retry
publication. A partial rerun that leaves candidates from an earlier attempt is
refused. A manual Checks run cannot produce release candidates.

Publication creates a draft, uploads all checked assets and publishes it.
Retry a failed **publish job only** to reuse its already signed assets (retained
for one day). Regenerating a signature can change its bytes and conflict with an
existing draft. Retries accept matching assets and notes, but never replace
conflicting assets or move tags. Configure immutable releases and tag protection as described in
[the maintainer guide](../DEVELOPERS.md).

## Download

Open [GitHub Releases](https://github.com/SupiVPN/supivpn/releases), choose a
version and download `supivpn-<version>-linux-arm64.tar.gz`, `SHA256SUMS` and
`SHA256SUMS.asc`.
Choose `linux-amd64` instead for x86-64 hosts. Assets are public: no token,
product checkout or custom download command is required.

For example, in a new directory, replacing the example version with a published one:

```bash
VERSION=v0.4.0
BASE="https://github.com/SupiVPN/supivpn/releases/download/$VERSION"
curl --fail --location --proto '=https' --proto-redir '=https' \
  --output "supivpn-$VERSION-linux-arm64.tar.gz" \
  "$BASE/supivpn-$VERSION-linux-arm64.tar.gz"
curl --fail --location --proto '=https' --proto-redir '=https' \
  --output SHA256SUMS "$BASE/SHA256SUMS"
curl --fail --location --proto '=https' --proto-redir '=https' \
  --output SHA256SUMS.asc "$BASE/SHA256SUMS.asc"
gpg --keyserver hkps://keys.openpgp.org --recv-keys A43155B36661034A4FA89E373681E6DFB83B35E2
gpg --fingerprint --with-subkey-fingerprint A43155B36661034A4FA89E373681E6DFB83B35E2
gpg --verify SHA256SUMS.asc SHA256SUMS
shasum -a 256 "supivpn-$VERSION-linux-arm64.tar.gz"
```

Stop if the signature verification fails. Verify the full primary and signing
subkey fingerprints against [the release-key policy](../DEVELOPERS.md#release-signing);
do not trust a key merely because its email or name matches.
Compare the printed hash with the line for that exact filename in `SHA256SUMS`
before extraction. Automation must fail on a missing or mismatching checksum
and validate the bundle contract below before installation. Pin the version
and retain the approved digest instead of silently following `latest`.

For automation, use GnuPG's machine-readable `VALIDSIG` status and require both
the pinned primary fingerprint and an authorized artifact-signing subkey. Reject
bad, revoked, expired or unknown signatures and missing checksum entries.
Do not continue to checksum verification after a failed signature check.

## Bundle contract

The archive name is `supivpn-<version>-linux-<arch>.tar.gz`.
`bundle.json.format` is 3. Its identity fields are `version`, `commit`,
`target`, and the exact `files` map containing each file's SHA-256 and size.

```text
bundle.json
release.json
LICENSE
THIRD_PARTY_NOTICES.md
THIRD_PARTY_LICENSES.txt
bin/
  supivpn
  supivpn-controller
  supivpn-profile
  supivpn-migrate
  bootstrap
  bootstrap-agent
  bootstrap-recovery
lambda/
  supivpn-lambda.zip
  supivpn-agent-lambda.zip
  supivpn-recovery-lambda.zip
migrations/
  NNN_name.sql
examples/
  client.ovpn.example
```

`release.json` describes database schema, migration digests, compatible schemas,
binary digests and the three Lambda components. Require an exact supported
format and allowlisted regular-file set. Refuse traversal, symlinks, hardlinks,
duplicate names, oversized members and unexpected files. Validate before
installing. The public Lambda ZIP contains `bootstrap` and
`client.ovpn.template`; agent/recovery ZIPs contain only `bootstrap`.

Runtime configuration, server certificates and keys are supplied separately by
the operator. The bundle does not include OpenVPN itself.

Each Release also includes `SHA256SUMS`, its detached signature `SHA256SUMS.asc`, and
`supivpn-source-<commit>.tar.gz`. The latter includes the exact original source,
vendored Go dependencies, toolchain notices and `SOURCE.json` with per-file
checksums. See [source distribution](OPEN_SOURCE.md).

Signed Git tags authenticate source identity. The signed checksum manifest
authenticates the exact published asset bytes under the release-signing policy.
It is not a proof that a build is reproducible or that its source is free of flaws.

## Compatibility

Prefer additive migrations and maintain old-reader compatibility where possible.
Never change released SQL bytes. Review schema digests and compatible versions,
back up the database, and use a coordinated cutover for incompatible changes.
Source history alone cannot prove runtime compatibility. Historical feature
notes are in [docs/history](history/).
