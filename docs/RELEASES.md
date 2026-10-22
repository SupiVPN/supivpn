# Release delivery

SupiVPN publishes Linux ARM64 and AMD64 bundles and Corresponding Source on
[GitHub Releases](https://github.com/SupiVPN/supivpn/releases). Both architectures
are tested natively; local Make commands default to the host architecture.

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
fuzzing. A separate job attests the exact binary archives, Debian packages,
Debian source and Corresponding Source downloaded from that same tag run.
Wait for the entire tag workflow,
including attestations and `Required checks`, to
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
both binary bundles, Debian packages and source, Corresponding Source and release
notes. The publication job
independently verifies the signature using the pinned primary and artifact subkey.
The workflow uses exact successful tag candidates retained for seven days.
It verifies the signed tag object and version, source commit, run/attempt,
archive digest, schema and architecture. Publication does not rebuild or
repackage the archives and cannot fall back to main or another tag.
Before preparation can reach the GPG signing job, `gh attestation verify`
cryptographically verifies each archive, Debian package and source descriptor
against the canonical repository,
Checks workflow, signed tag ref and commit, and GitHub-hosted runner identity.
The verified certificate must also identify that exact run and attempt and a
push event. Workflow-supplied predicate text is not trusted for these bindings.
Missing provenance, verification errors and unavailable verification services
stop preparation; there is no fallback to checksums alone.
If candidates expired, rerun **all jobs** of the original tag push run, then retry
publication. A partial rerun that leaves candidates from an earlier attempt is
refused. A manual Checks run cannot produce release candidates.
Tags created before the attestation job was added cannot gain this evidence by
rerunning their older workflow. Publish a new reviewed version containing the
job; existing release assets remain verifiable with their GPG signatures.

Only the canonical tag-only attestation job receives `id-token: write` and
`attestations: write`. It runs pinned download/attestation actions without a
source checkout, build scripts, caches or release keys. PR/main checks retain
read-only token permissions. Release preparation receives `attestations: read`;
GPG signing and publication keep their existing permissions.
Stable releases additionally generate and sign the APT indexes in that protected
signing job. After release publication, a separate Pages job receives
`pages: write` and `id-token: write` to publish the verified repository.
See [APT operations](APT_REPOSITORY.md) for first-time hosting and recovery.

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

## Debian downloads

Releases built with Debian delivery include `supivpn-node_<version>_<arch>.deb`,
`supivpn-controller_<version>_<arch>.deb` and `supivpn_<version>_all.deb`, where
`<arch>` is `amd64` or `arm64`. Debian versions omit the leading `v`; prereleases
use `~rc.N`, `~beta.N` or `~alpha.N`. The matching native source is supplied as
`supivpn_<version>.dsc` and `supivpn_<version>.tar.xz`. These files are all covered
by `SHA256SUMS.asc` and GitHub attestations. Individual `.deb`/`.dsc` files do not
carry embedded OpenPGP signatures; verify the signed checksum manifest first.

Stable releases also populate [apt.supivpn.com](https://apt.supivpn.com);
[DEPLOYMENT.md](../DEPLOYMENT.md#add-the-supivpn-repository) uses APT for installation.
See [APT operations](APT_REPOSITORY.md) for Pages setup, signing, retention and recovery.
**The first APT deployment is still pending; v0.5.0 and earlier have no `.deb`
assets.** Preparation refuses missing packages, mismatched version/architecture,
modified source, missing provenance or different shared assets across builds.

## Download and verify SupiVPN

Replace `vX.Y.Z` with the chosen release containing `.deb` assets. Run this block
in Bash; it stops on download, signature or checksum failure. It creates a new
version/architecture directory, refusing to mix with earlier downloads:

```bash
set -euo pipefail
VERSION=vX.Y.Z
ARCH=$(dpkg --print-architecture)
case "$ARCH" in amd64|arm64) ;; *) exit 1 ;; esac
DEB_VERSION=${VERSION#v}
DEB_VERSION=${DEB_VERSION/-/\~}
BASE="https://github.com/SupiVPN/supivpn/releases/download/$VERSION"
install -d -m 0700 /root/supivpn-packages
mkdir "/root/supivpn-packages/$VERSION-$ARCH"
cd "/root/supivpn-packages/$VERSION-$ARCH"
PACKAGES=("supivpn-node_${DEB_VERSION}_${ARCH}.deb"
          "supivpn-controller_${DEB_VERSION}_${ARCH}.deb" "supivpn_${DEB_VERSION}_all.deb")
for FILE in "${PACKAGES[@]}" SHA256SUMS SHA256SUMS.asc; do
  curl --fail --show-error --location --proto '=https' --proto-redir '=https' -o "$FILE" "$BASE/$FILE"
done
PRIMARY=A43155B36661034A4FA89E373681E6DFB83B35E2
SIGNER=867CC295DFBEE8E0888F7AFF113339EEAC58A9C5
mkdir -m 0700 verification-keyring
gpg --homedir ./verification-keyring --batch --keyserver hkps://keys.openpgp.org --recv-keys "$PRIMARY"
gpg --homedir ./verification-keyring --batch --status-fd 1 \
  --verify SHA256SUMS.asc SHA256SUMS > signature.status
awk -v primary="$PRIMARY" -v signer="$SIGNER" '
  $1 == "[GNUPG:]" && $2 == "VALIDSIG" && $3 == signer && $NF == primary { valid=1 }
  $1 == "[GNUPG:]" && $2 ~ /^(BADSIG|ERRSIG|EXPSIG|EXPKEYSIG|REVKEYSIG|KEYEXPIRED|KEYREVOKED|NO_PUBKEY)$/ { bad=1 }
  END { exit !(valid && !bad) }
' signature.status
for FILE in "${PACKAGES[@]}"; do
  awk -v name="$FILE" '$2 == name { print; found++ } END { exit (found != 1) }' SHA256SUMS > selected.sha256
  sha256sum --check --strict selected.sha256
done
```

The pinned fingerprints come from the [release-key policy](../DEVELOPERS.md#release-signing).
Do not bypass verification on failure. Release preparation also verifies GitHub
build provenance for every package; [independent provenance verification](#verify-build-provenance)
is available with `gh` on a workstation. Keep the signed checksum files with the
packages for later inspection. After installing the dependencies in DEPLOYMENT.md,
install these exact files with `apt-get install "${PACKAGES[@]/#/./}"`.

## Verify build provenance

For releases built after provenance was introduced, verify the downloaded
archive with a current [GitHub CLI](https://cli.github.com/manual/gh_attestation_verify)
in addition to the GPG signature and checksum checks above. Set `VERSION` to the
selected release and `COMMIT` to its full commit SHA from the authenticated
release notes or verified signed tag:

```bash
gh attestation verify "supivpn-$VERSION-linux-arm64.tar.gz" \
  --repo SupiVPN/supivpn --hostname github.com \
  --cert-identity "https://github.com/SupiVPN/supivpn/.github/workflows/checks.yml@refs/tags/$VERSION" \
  --cert-oidc-issuer https://token.actions.githubusercontent.com \
  --source-ref "refs/tags/$VERSION" --source-digest "$COMMIT" \
  --signer-digest "$COMMIT" --deny-self-hosted-runners \
  --predicate-type https://slsa.dev/provenance/v1
```

Use the AMD64 filename, `supivpn-source-$COMMIT.tar.gz`, or any downloaded `.deb`,
`.dsc` or Debian `.tar.xz` filename to verify that asset.
Stop on verification failure. The CLI retrieves evidence from GitHub and verifies
its Sigstore signatures, subject digest and certificate policy. Release
preparation additionally binds the certificate's run/attempt to its selected
successful Checks run.

Provenance links these bytes to the tag's GitHub workflow execution. It does not
prove that the source is safe, dependencies are harmless or builds are
reproducible. GPG remains the release authority; attestations add evidence of
build origin. The workflow uses the pinned
[actions/attest](https://github.com/actions/attest) implementation of build
provenance without publishing a container or using a persistent signing key.

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
