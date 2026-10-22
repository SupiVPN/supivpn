# SupiVPN APT repository

Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
See [LICENSE](../LICENSE) for copyright ownership and licensing terms.

`https://apt.supivpn.com` serves stable packages for Debian 13 (`trixie`),
component `main`, architectures `amd64` and `arm64`, plus native Debian source.
The `supivpn` metapackage installs `supivpn-node` and `supivpn-controller` at
matching versions. See [the installation guide](../DEPLOYMENT.md).

**Launch status:** [v0.6.0](https://github.com/SupiVPN/supivpn/releases/tag/v0.6.0)
is published on GitHub Releases and the signed APT repository over HTTPS.
Live acceptance verified both architectures, source, dependency downloads and
equality with the signed release assets. v0.5.0 and earlier have no Debian assets.
No VPN service was deployed by these download-only checks.

## Delivery

```text
signed version tag -> native Checks + provenance -> Release preparation
  -> exact .deb/.dsc/source from successful tag builds
  -> previous two stable package releases verified by signed SHA256SUMS
  -> reprepro indexes + by-hash copies
  -> protected release environment: checksum and APT signatures
  -> publish GitHub Release -> verify APT tree -> GitHub Pages
```

Only a reviewed `Release` workflow dispatch on canonical main can publish.
PR/main Checks exercise the generator with disposable keys and packages, with
read-only permissions. Prereleases get GitHub Release assets but never update
APT. An older stable tag cannot replace a newer published stable version.

`reprepro` runs without signing credentials. It imports the exact verified
packages without rebuilding them, and creates `Packages`, `Sources`, `Release`
and compressed indexes. The protected `release` job signs `Release.gpg` and
`InRelease` with the existing artifact-signing subkey. Its temporary keyring
accepts only that private subkey and a primary-key stub; it cannot use the tag
key. No new working key, token or signing secret is required.

Signing has no GitHub token. Release publication and Pages deployment have
separate job permissions. The final Pages job has only `pages: write` and
`id-token: write`, runs the pinned deploy action and has no source checkout or
signing secrets. Only `out/apt/site/` is published: never the `reprepro` database,
download workspace, prepared manifest or private keyring.

Both OpenPGP signatures, every prepared file and every SHA256 index are checked
again before the Pages artifact is uploaded. Clients pin the release certificate
through `Signed-By`; the published certificate contains only its artifact-signing
subkey. This works with Debian 13's sqv verification backend, which does not
support pinning a subkey fingerprint with `!`. Trust is scoped to this repository. Never disable APT
authentication to work around a missing or invalid signature.

## One-time hosting setup

These are maintainer operations requiring explicit authorization for the named
resources. Preparing source changes does not configure the services.

1. In **SupiVPN/supivpn**, enable Settings -> Pages -> **GitHub Actions**. Set
   custom domain **apt.supivpn.com** before creating the DNS record. This uses
   the product repository; the separate `SupiVPN/supivpn.github.io` website and
   its `supivpn.com` domain are unchanged.
2. Restrict the `github-pages` environment to protected `main`. Retain the
   existing `release` environment reviewers and signing secrets. Review the new
   Pages permissions and the existing public-key variable
   `SUPIVPN_GPG_PUBLIC_KEY`; it must contain the published release primary and
   artifact subkey from `ci/signers.json`, with current validity information.
3. In the `supivpn.com` DNS zone, add **CNAME apt -> supivpn.github.io**, DNS only.
   Avoid Cloudflare proxy/cache rules for this host. Do not change the apex,
   mail, VPN or other records. Keep GitHub domain verification in place; add
   the exact owner-verification TXT record GitHub supplies only if needed.
4. After GitHub reports the domain valid and provisions its certificate,
   enforce HTTPS. Do not publish installation instructions as operational
   until HTTPS and the first signed repository both work.
5. Publish a new stable signed release containing Debian delivery and APT
   support using the [release procedure](RELEASES.md#create-a-release). Review
   both native tag checks, exact target, signed tag and intended Release/Pages
   publication before approving the publication batch.

GitHub documents [custom workflows](https://docs.github.com/en/pages/getting-started-with-github-pages/using-custom-workflows-with-github-pages)
and [custom domains](https://docs.github.com/en/pages/configuring-a-custom-domain-for-your-github-pages-site/managing-a-custom-domain-for-your-github-pages-site).

## Retention, caching and updates

The APT indexes advertise the newest stable version. The pool retains that
version and the previous two stable package releases, with their source and
index-by-hash copies. Cached indexes can still fetch their matching packages
across those deployments. Older versions remain in GitHub Releases. There is
no mutable `gh-pages` binary history or long-lived `reprepro` database: each
deployment reconstructs the repository from authenticated release assets.

The site is capped at **800 MiB** and 1,024 files, below the
[GitHub Pages size limit](https://docs.github.com/en/pages/getting-started-with-github-pages/github-pages-limits).
Preparation fails rather than silently dropping retention or source. Review a
hosting/retention change if those bounds are reached. GitHub Pages is suitable
for this initial download volume; monitor its bandwidth limits as use grows.

Indexes are refreshed on stable releases; there is no scheduled signing job.
`Release` currently has no `Valid-Until` expiry, so an old correctly signed
snapshot remains cryptographically valid until its signing key expires.
HTTPS, immutable release assets and the publication version check do not provide
client-side freshness against replay. A future expiry policy must include a
reviewed refresh schedule and outage handling; do not add an expiry alone.

For upgrades, review release notes and back up PostgreSQL first. Then:

```bash
sudo apt-get update
apt-cache policy supivpn supivpn-node supivpn-controller
sudo apt-get install --only-upgrade supivpn supivpn-node supivpn-controller
```

Package upgrades preserve configuration and do not automatically migrate the
database or restart running services. Complete the migration/restart procedure
in [deployment maintenance](../DEPLOYMENT.md#maintenance-and-troubleshooting).
To fetch corresponding source, add `deb-src` to `Types` in `supivpn.sources`, run
`apt-get update`, then `apt-get source supivpn` in a fresh working directory.

## Verification and recovery

Local integration tests use synthetic package versions and ephemeral signing
keys. They build both architecture indexes with real `reprepro`, fetch them over
loopback with real APT, resolve and download all three packages for each
architecture, and reject altered signatures and package bytes. No packages are
installed on the workstation and no working keys are accessed.

```bash
docker build -f ci/apt/Dockerfile -t supivpn-apt-test:trixie ci/apt
docker run --rm --network none --cap-drop ALL --security-opt no-new-privileges \
  --mount type=bind,source="$PWD/tools",target=/work/tools,readonly \
  --workdir /work supivpn-apt-test:trixie
```

After first publication, repeat `apt-get update`, `apt-cache policy` and a
download-only installation on a disposable Debian VM against the actual HTTPS
domain. Confirm the public key fingerprint, both architectures, source retrieval
and the GitHub Pages deployment result. Local tests do not replace this check.

If Pages fails after Release publication, the release assets remain available
and the previous APT deployment remains active. Retry only the failed Pages
verification/deployment jobs while their signed artifact is retained (one day).
Do not rerun signing over an existing release: its newly generated checksum
signature can conflict with immutable assets. After artifact expiry, use a new
reviewed release. A rollback of live APT contents needs a separate reviewed
procedure; this pipeline intentionally refuses an older version.

Never republish altered packages under an existing version, replace a signed
tag, disable signature checks or expose a secret to recover a failed run.
