# Maintainer guide

For local development and pull requests, start with [CONTRIBUTING.md](CONTRIBUTING.md).
Use [BUILD.md](BUILD.md) for targeted test commands and GoLand configuration.

## Repository controls

Protect `main` with pull requests, the `Required checks` status check, dismissed
stale approvals, and code-owner review for security-sensitive changes. Restrict
bypass privileges to the minimum needed for recovery. Require approval before
workflows from outside contributors run.

Use read-only workflow permissions by default. Checks run on standard
GitHub-hosted ARM64 and AMD64 runners and do not receive release credentials.
Do not use `pull_request_target` to execute contributor code.

Restrict creation, updates and deletion of `v*` tags to release maintainers.
Enable immutable releases. Configure the `release` environment for the default
branch only and require a maintainer review before publication. A sole maintainer
must allow their own environment approval until another reviewer is available.

## Release signing

Maintain the release-signing fingerprints in `ci/signers.json`. Configure the
`SUPIVPN_GPG_PUBLIC_KEY` repository Actions variable with the complete armored
public key for those fingerprints. Keep the primary key and tag-signing subkey
with maintainers. Only the dedicated artifact-signing subkey is available to CI.

Contributor commits do not have to use a maintainer key. Reviewed changes enter
`main` through pull requests; release tags require an authorized OpenPGP signature.
Review signer-policy changes as security changes.

Use a dedicated release identity, **SupiVPN Releases <release@supivpn.com>**,
with its own primary key rather than another UID on a personal key. Keep the
primary key and revocation certificate offline; use an expiring signing subkey
on the maintainer workstation or hardware token.

The current release key uses a certification-only Ed25519 primary key and
separate Ed25519 signing subkeys:

- Primary fingerprint: `A43155B36661034A4FA89E373681E6DFB83B35E2`
  (expires 2036-10-17).
- Local tag-signing subkey: `6C7A3DDF51331D58E0C25EDCFAC49FA8FBB7640F`
  (expires 2027-10-20).
- CI artifact-signing subkey: `867CC295DFBEE8E0888F7AFF113339EEAC58A9C5`
  (expires 2027-10-20).
- [Download the public key](https://keys.openpgp.org/vks/v1/by-fingerprint/A43155B36661034A4FA89E373681E6DFB83B35E2).

The signer policy pins both the primary fingerprint and separate subkey
allowlists for tags and artifacts. A CI artifact key cannot authorize a release
tag. Update the public-key variable, published public key, and relevant subkey
allowlist together when rotating a subkey.

Configure your own commit identity and signing key locally. `make tag` explicitly
selects the authorized tag subkey from `ci/signers.json`, independently of
`user.signingkey`, and records the release identity as the tagger. If several
tag subkeys are allowed, select one using
`SUPIVPN_TAG_SIGNING_SUBKEY=<full-fingerprint>`.

Configure these **environment secrets** in the protected `release` environment:

- `SUPIVPN_ARTIFACT_SIGNING_KEY`: armored, passphrase-protected export of only
  the CI signing subkey, with an unusable primary-key stub.
- `SUPIVPN_ARTIFACT_SIGNING_PASSPHRASE`: its passphrase.

Export the exact CI subkey using `gpg --armor --export-secret-subkeys '<subkey>!'`
directly into a secure secret-upload workflow; never export the primary private
key. Verify the imported key inventory before uploading. Do not store the export
in the repository or a job artifact.

Require an approved maintainer for this environment, restrict it to the `main`
branch, and disable administrative bypass. A sole maintainer may approve their
own run; disable self-approval once another reviewer is available. Review
changes to the workflow, signer policy and signing tools through protected
pull requests. Environment approval does not make arbitrary workflow code safe.

Only the `sign` job receives these secrets, after approval, with read-only
repository permissions. It imports the subkey into a temporary GnuPG home,
rejects a usable primary key or additional private keys, signs `SHA256SUMS`,
verifies the signature, then removes the keyring. The separate `publish` job
receives no signing secret and verifies the signature before any release write.
Never enable shell tracing or runner debug logging for signing jobs.

When introducing or rotating that key, verify the full primary fingerprint
out of band, update `ci/signers.json` through review, and update the public-key
Actions variable together. Publish the reviewed public key and full fingerprint
on the project website. It can also be uploaded to
[keys.openpgp.org](https://keys.openpgp.org/about/) after verifying the release
email address. A keyserver distributes keys; it does not authorize release signers.
Retain the public keys needed to verify earlier releases.

## Release operation

Follow [release delivery](docs/RELEASES.md). Pushing a signed version tag runs
parallel checks and native builds for its exact commit. The separate Release
workflow runs from protected main and publishes only the matching successful
tag artifacts; it never substitutes the current main build. Release preparation
requires the complete tag workflow to succeed, including every matrix leg.
Review the generated release notes, configuration and database compatibility
before publishing. Prefer additive, compatible migrations; never edit an
already released migration.

Report vulnerabilities through [SECURITY.md](SECURITY.md).
