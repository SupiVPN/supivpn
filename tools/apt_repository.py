# Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
# SPDX-License-Identifier: AGPL-3.0-only
"""Build a bounded reprepro repository from verified release assets; never deploy."""
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

import artifacts as a
import artifact_signing
import debian_release as deb
import github_api as gh
import github_release as release
import signatures

ROOT = Path(__file__).resolve().parents[1]
DOMAIN = "apt.supivpn.com"
SUITE = "trixie"
KEEP = 3
MAX_SITE = 800 * 1024 * 1024
STABLE = re.compile(r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)")


def order(version):
    a.require(isinstance(version, str) and len(version) <= 64 and STABLE.fullmatch(version),
              "APT requires a stable semantic version")
    return tuple(map(int, version[1:].split(".")))


def package_names(version):
    order(version)
    return deb.filenames(version, "amd64") | deb.filenames(version, "arm64")


def history(version):
    """Never promote an old release over a newer stable release; exclude drafts/RCs."""
    target = order(version)
    records = []
    for page in range(1, 11):
        batch = gh.api(f"releases?per_page=100&page={page}")
        a.require(isinstance(batch, list), "Invalid release history")
        records.extend(batch)
        if len(batch) < 100:
            break
    else:
        raise a.ValidationError("Release history exceeds reviewed limit")
    eligible, seen = [], set()
    for item in records:
        name = item.get("tag_name", "")
        if item.get("draft") is not False or item.get("prerelease") is not False or not STABLE.fullmatch(name):
            continue
        a.require(name not in seen, "Duplicate stable release")
        seen.add(name)
        a.require(order(name) <= target, "APT rollback refused: a newer stable release exists")
        names = {entry.get("name") for entry in item.get("assets", [])}
        required = package_names(name)
        # Older releases predate Debian delivery. Partially populated releases are errors.
        if names & required:
            a.require(required | {"SHA256SUMS", "SHA256SUMS.asc"} <= names,
                      "Published Debian release is incomplete")
            if name != version:
                eligible.append(item)
    return sorted(eligible, key=lambda item: order(item["tag_name"]))[-(KEEP - 1):]


def download(item, directory, policy):
    version = item["tag_name"]
    names = package_names(version) | {"SHA256SUMS", "SHA256SUMS.asc"}
    entries = item.get("assets", [])
    assets = {entry.get("name"): entry for entry in entries}
    a.require(len(assets) == len(entries) and names <= assets.keys(), "Ambiguous release assets")
    directory.mkdir()
    for name in sorted(names):
        asset = assets[name]
        limit = 8192 if name.startswith("SHA256SUMS") else a.MAX_BUNDLE
        a.require(type(asset.get("id")) is int and asset["id"] > 0
                  and type(asset.get("size")) is int and 0 < asset["size"] <= limit
                  and asset.get("state") == "uploaded", "Invalid published Debian asset")
        status, raw = gh.request(gh.API + "releases/assets/" + str(asset["id"]),
                                 accept="application/octet-stream", limit=limit)
        a.require(status == 200 and len(raw) == asset["size"], "Debian asset download failed")
        (directory / name).write_bytes(raw)
    artifact_signing.verify(directory / "SHA256SUMS", directory / "SHA256SUMS.asc", policy)
    sums = {}
    for line in a.regular(directory / "SHA256SUMS", 8192).decode("ascii").splitlines():
        fields = line.split("  ")
        a.require(len(fields) == 2 and a.HEX.fullmatch(fields[0])
                  and re.fullmatch(r"[a-zA-Z0-9_.~-]+", fields[1]) and fields[1] not in sums,
                  "Malformed signed release checksums")
        sums[fields[1]] = fields[0]
    for name in package_names(version):
        a.require(name in sums and a.sha(a.regular(directory / name, a.MAX_BUNDLE)) == sums[name],
                  "Published Debian checksum mismatch")
    return directory


def command(args):
    result = subprocess.run(args, capture_output=True, timeout=120)
    a.require(result.returncode == 0, "APT repository command failed")
    return result.stdout


def release_indexes(site):
    """Validate the SHA256 section without following paths outside dists/trixie."""
    root = site / "dists" / SUITE
    raw = a.regular(root / "Release", 65536)
    text = raw.decode("ascii")
    for line in ("Origin: SupiVPN", "Label: SupiVPN", "Suite: trixie", "Codename: trixie"):
        a.require(line in text.splitlines(), "APT Release identity mismatch")
    sections = text.split("\nSHA256:\n")
    a.require(len(sections) == 2, "APT SHA256 indexes missing")
    indexes = {}
    for row in sections[1].splitlines():
        if not row.startswith(" "):
            break
        fields = row.split()
        a.require(len(fields) == 3 and a.HEX.fullmatch(fields[0]) and fields[1].isdigit(),
                  "Invalid APT index record")
        name = fields[2]
        a.require(re.fullmatch(r"main/(binary-(amd64|arm64)|source)/(Packages|Sources|Release)(\.gz)?", name)
                  and name not in indexes, "Unexpected APT index path")
        data = a.regular(root / name, 4 * 1024 * 1024)
        a.require(len(data) == int(fields[1]) and a.sha(data) == fields[0], "APT index checksum mismatch")
        indexes[name] = data
    a.require({"main/binary-amd64/Packages", "main/binary-arm64/Packages", "main/source/Sources"}
              <= indexes.keys(), "Required APT indexes missing")
    return indexes


def by_hash(site):
    root = site / "dists" / SUITE
    for name, data in release_indexes(site).items():
        path = (root / name).parent / "by-hash" / "SHA256" / a.sha(data)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    path = root / "Release"
    raw = a.regular(path, 65536)
    if b"\nAcquire-By-Hash: yes\n" not in raw:
        path.write_bytes(b"Acquire-By-Hash: yes\n" + raw)


def source_entry(policy, *, uri="https://" + DOMAIN, key="/etc/apt/keyrings/supivpn.asc"):
    a.require(len(policy["release_signers"]) == 1, "Select one reviewed APT certificate")
    return (f"Types: deb\nURIs: {uri}\nSuites: {SUITE}\nComponents: main\n"
            "Architectures: amd64 arm64\nSigned-By: " + key + " "
            + policy["release_signers"][0] + "\n")


def apt_public_key(public, policy):
    """Publish a public certificate containing only the artifact-signing subkey."""
    a.require(0 < len(public) <= 65536 and public.startswith(b"-----BEGIN PGP PUBLIC KEY BLOCK-----")
              and public.count(b"-----BEGIN PGP ") == 1 and b"PRIVATE KEY" not in public,
              "APT public key required")
    a.require(len(policy["release_signers"]) == len(policy["artifact_signing_subkeys"]) == 1,
              "Select one reviewed APT certificate and signing subkey")
    with tempfile.TemporaryDirectory(prefix="apt-public-") as temp:
        args = ["gpg", "--no-options", "--homedir", temp, "--batch", "--no-autostart", "--no-auto-key-retrieve"]
        result = subprocess.run([*args, "--import"], input=public, capture_output=True, timeout=30)
        a.require(result.returncode == 0, "APT public key import failed")
        # GnuPG uses <> for string inequality; != compares numeric prefixes.
        result = subprocess.run([*args, "--armor", "--export-options", "export-minimal",
                                 "--export-filter", "drop-subkey=fpr <> " + policy["artifact_signing_subkeys"][0],
                                 "--export", policy["release_signers"][0]], capture_output=True, timeout=30)
        a.require(result.returncode == 0 and 0 < len(result.stdout) <= 65536, "APT public key export failed")
        exported = result.stdout
        result = subprocess.run([*args, "--with-colons", "--show-keys"], input=exported,
                                capture_output=True, timeout=30)
        fingerprints = [line.split(":")[9] for line in result.stdout.decode().splitlines() if line.startswith("fpr:")]
        a.require(result.returncode == 0 and fingerprints == policy["release_signers"] + policy["artifact_signing_subkeys"],
                  "APT public key contains unexpected keys")
        return exported


def tree(site):
    result, size = {}, 0
    for path in sorted(site.rglob("*")):
        a.require(not path.is_symlink(), "APT links refused")
        if path.is_dir():
            continue
        raw = a.regular(path, a.MAX_BUNDLE)
        size += len(raw)
        a.require(size <= MAX_SITE and len(result) < 1024, "APT Pages size limit exceeded")
        result[path.relative_to(site).as_posix()] = a.sha(raw)
    return result


def build(output, version, packages, public, policy):
    """Packages must already be bound to successful tag builds or signed releases."""
    order(version)
    a.require(not output.exists(), "APT output already exists")
    a.require(1 <= len(packages) <= KEEP and packages[-1][0] == version
              and [order(v) for v, _ in packages] == sorted({order(v) for v, _ in packages}),
              "APT versions must be unique and increasing")
    site, base = output / "site", output / "reprepro"
    site.mkdir(parents=True)
    (base / "conf").mkdir(parents=True)
    (base / "conf/distributions").write_text(
        "Origin: SupiVPN\nLabel: SupiVPN\nSuite: trixie\nCodename: trixie\n"
        "Architectures: amd64 arm64 source\nComponents: main\n"
        "Description: SupiVPN stable releases for Debian 13\n"
        "DebIndices: Packages Release . .gz\nDscIndices: Sources Release . .gz\n")
    args = ["reprepro", "--basedir", str(base), "--outdir", str(site), "--keepunreferenced",
            "--export=never"]
    expected_pool = {}
    pool_size = 0
    old_hashes = {}
    for name, directory in packages:
        for filename in sorted(package_names(name)):
            path = directory / filename
            raw = a.regular(path, a.MAX_BUNDLE)
            pool_size += len(raw)
            a.require(pool_size <= MAX_SITE, "APT package pool size limit exceeded")
            expected_pool[filename] = a.sha(raw)
            if filename.endswith(".deb"):
                arch = "amd64" if filename.endswith(("_amd64.deb", "_all.deb")) else "arm64"
                deb.verify_package(path, name, arch)
                command([*args, "--component", "main", "includedeb", SUITE, str(path)])
        command([*args, "--component", "main", "--section", "net", "--priority", "optional", "includedsc", SUITE,
                 str(directory / f"supivpn_{deb.version(name)}.dsc")])
        command([*args[:-1], "export", SUITE])
        by_hash(site)
        for path in (site / "dists").rglob("by-hash/SHA256/*"):
            old_hashes[path.relative_to(site)] = path.read_bytes()
    # Some reprepro versions clean unknown index paths when exporting.
    for path, raw in old_hashes.items():
        (site / path).parent.mkdir(parents=True, exist_ok=True)
        (site / path).write_bytes(raw)
    actual_pool = {p.name: a.sha(a.regular(p, a.MAX_BUNDLE)) for p in (site / "pool").rglob("*") if p.is_file()}
    a.require(actual_pool == expected_pool, "APT pool differs from verified release assets")
    (site / "supivpn.asc").write_bytes(apt_public_key(public, policy))
    (site / "supivpn.sources").write_text(source_entry(policy))
    (site / "CNAME").write_text(DOMAIN + "\n")
    (site / ".nojekyll").touch()
    (site / "index.html").write_text(
        '<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" '
        'content="width=device-width"><title>SupiVPN APT</title><h1>Go Supi!</h1>'
        '<p>Your team. Your tunnel. Your rules.</p><p>Signed Debian 13 packages for AMD64 and ARM64.</p>'
        '<p><a href="https://github.com/SupiVPN/supivpn/blob/main/DEPLOYMENT.md">Installation guide</a> '
        '| <a href="supivpn.asc">Public signing key</a> | <a href="supivpn.sources">APT source</a></p>'
        '<p>Current release: ' + version + '</p></html>\n')
    (output / "prepared.json").write_text(json.dumps(
        {"version": version, "versions": [v for v, _ in packages], "files": tree(site)}, sort_keys=True) + "\n")


def validate(output, version, policy, *, signed=False):
    order(version)
    metadata = a.json_object(a.regular(output / "prepared.json", 256 * 1024))
    a.require(metadata.get("version") == version, "APT target changed")
    site = output / "site"
    files = tree(site)
    if signed:
        files.pop("dists/trixie/InRelease", None)
        files.pop("dists/trixie/Release.gpg", None)
    a.require(files == metadata.get("files"), "Prepared APT files changed")
    a.require((site / "CNAME").read_text() == DOMAIN + "\n"
              and (site / "supivpn.sources").read_text() == source_entry(policy), "APT endpoint changed")
    indexes = release_indexes(site)
    for name, data in indexes.items():
        path = (site / "dists/trixie" / name).parent / "by-hash/SHA256" / a.sha(data)
        a.require(a.regular(path, 4 * 1024 * 1024) == data, "APT by-hash index missing")
    if signed:
        manifest = site / "dists/trixie/Release"
        artifact_signing.verify(manifest, manifest.with_name("Release.gpg"), policy, limit=65536)
        artifact_signing.verify_inline(manifest, manifest.with_name("InRelease"), policy)


def prepare(version, output, current, policy):
    release.checked_release(current, version)
    previous = history(version)
    downloads = output.with_name("apt-inputs")
    downloads.mkdir()
    packages = [(item["tag_name"], download(item, downloads / item["tag_name"], policy)) for item in previous]
    packages.append((version, current))
    build(output, version, packages, os.environ["SUPIVPN_GPG_PUBLIC_KEY"].encode(), policy)


def published(version, site):
    item = gh.api("releases/tags/" + version)
    a.require(item.get("tag_name") == version and item.get("draft") is False
              and item.get("prerelease") is False, "Stable release publication missing")
    entries = item.get("assets", [])
    assets = {entry.get("name"): entry for entry in entries}
    a.require(len(assets) == len(entries), "Duplicate published assets")
    for name in package_names(version):
        paths = list((site / "pool").rglob(name))
        a.require(len(paths) == 1 and name in assets, "Published APT package missing")
        raw = a.regular(paths[0], a.MAX_BUNDLE)
        a.require(assets[name].get("state") == "uploaded" and assets[name].get("size") == len(raw)
                  and assets[name].get("digest") == "sha256:" + a.sha(raw), "Published APT package differs")


def main():
    try:
        version = release.workflow_context(os.environ)
        order(version)
        policy = signatures.read_policy(ROOT / "ci/signers.json")
        output = ROOT / "out/apt"
        mode = sys.argv[1:]
        if mode == ["prepare"]:
            with release.public_keyring():
                prepare(version, output, ROOT / "out/github-release", policy)
        elif mode == ["sign"]:
            validate(output, version, policy)
            artifact_signing.sign(output / "site/dists/trixie/Release", policy, apt=True)
        elif mode == ["verify"]:
            with release.public_keyring():
                validate(output, version, policy, signed=True)
                history(version)
                published(version, output / "site")
        else:
            raise a.ValidationError("Expected prepare, sign or verify")
        print("APT " + mode[0] + " completed for " + version)
        return 0
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        print("APT operation refused; check stable version, verified assets and repository integrity.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
