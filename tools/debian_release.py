# Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
# SPDX-License-Identifier: AGPL-3.0-only
"""Exact Debian release filenames, versioning and source/payload validation."""
from datetime import datetime, timezone
from email.utils import format_datetime
import io
import subprocess
import tarfile

import artifacts as a
import tag_release
import source_archive


def version(tag):
    a.require(isinstance(tag, str) and len(tag) <= 64 and tag_release.VERSION.fullmatch(tag),
              "Invalid Debian release version")
    return tag[1:].replace("-", "~")


def filenames(tag, arch):
    a.architecture(arch)
    value = version(tag)
    names = {f"supivpn-node_{value}_{arch}.deb", f"supivpn-controller_{value}_{arch}.deb",
             f"supivpn_{value}_all.deb", f"supivpn_{value}.dsc", f"supivpn_{value}.tar.xz"}
    if has_cli(tag):
        names.add(f"supivpn-cli_{value}_{arch}.deb")
    return names


def has_cli(tag):
    # Keep historical APT inputs valid. CLI delivery begins with the next minor
    # series; patch releases on the existing 0.6/0.7 lines retain their payloads.
    version(tag)
    return tuple(map(int, tag[1:].split("-", 1)[0].split("."))) >= (0, 8, 0)


def commit_epoch(root, commit):
    raw = source_archive.command(root, ["git", "show", "-s", "--format=%ct", commit]).strip()
    a.require(raw.isdigit() and 0 < int(raw) < 253402300800, "Invalid source timestamp")
    return int(raw)


def changelog(original, tag, epoch):
    value = version(tag)
    a.require(type(epoch) is int and 0 < epoch < 253402300800, "Invalid source timestamp")
    date = format_datetime(datetime.fromtimestamp(epoch, timezone.utc))
    entry = (f"supivpn ({value}) trixie; urgency=medium\n\n"
             f"  * Package signed release {tag}; see the accompanying release notes.\n\n"
             f" -- Stanislav Kazachkov <enot@supivpn.com>  {date}\n\n")
    return entry.encode() + original


def verify_source(raw, dsc, tag, originals, epoch):
    """Inspect source without extraction or executing package code."""
    value = version(tag)
    files, total = {}, 0
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:xz") as archive:
        for member in archive:
            parts = member.name.split("/")
            a.require(parts[0] == "source" and all(p not in {"", ".", ".."} for p in parts),
                      "Unsafe Debian source path")
            if member.isdir():
                continue
            name = "/".join(parts[1:])
            a.require(name and member.isfile() and name not in files and len(files) < 10000
                      and 0 <= member.size <= 16 * 1024 * 1024, "Unsafe Debian source member")
            total += member.size
            a.require(total <= a.MAX_BUNDLE, "Debian source too large")
            files[name] = archive.extractfile(member).read(member.size + 1)
    expected = {name: data for name, (data, _) in originals.items()}
    # dpkg-source omits this VCS ignore file from native source tarballs.
    # The separately published exact Git source archive still includes it.
    expected.pop(".gitignore", None)
    expected["debian/changelog"] = changelog(expected["debian/changelog"], tag, epoch)
    a.require({name: data for name, data in files.items() if not name.startswith("vendor/")} == expected
              and "vendor/modules.txt" in files, "Debian source differs from signed tag")
    # The native source descriptor must name and hash exactly this source archive.
    text = dsc.decode("utf-8")
    a.require(text.startswith("Format: 3.0 (native)\n")
              and "\nSource: supivpn\n" in text and f"\nVersion: {value}\n" in text,
              "Debian source descriptor identity mismatch")
    section = text.split("\nChecksums-Sha256:\n")
    a.require(len(section) == 2, "Debian source checksum missing")
    rows = []
    for line in section[1].splitlines():
        if not line.startswith(" "):
            break
        rows.append(line.split())
    a.require(rows == [[a.sha(raw), str(len(raw)), f"supivpn_{value}.tar.xz"]],
              "Debian source descriptor checksum mismatch")


def verify_package(path, tag, arch):
    # dpkg-deb reads the control record; it never installs or runs maintainer scripts.
    reply = subprocess.run(["dpkg-deb", "-f", str(path), "Package", "Version", "Architecture", "Depends"],
                           capture_output=True, text=True, timeout=30, check=True)
    fields = dict(line.split(": ", 1) for line in reply.stdout.splitlines())
    package = fields.get("Package")
    expected_arch = "all" if package == "supivpn" else arch
    allowed = {"supivpn", "supivpn-node", "supivpn-controller"}
    if has_cli(tag):
        allowed.add("supivpn-cli")
    a.require(package in allowed
              and fields.get("Version") == version(tag) and fields.get("Architecture") == expected_arch
              and path.name == f"{package}_{version(tag)}_{expected_arch}.deb",
              "Debian package identity mismatch")
    if package in {"supivpn", "supivpn-cli"}:
        required = {"supivpn-node", "supivpn-controller"}
        if package == "supivpn" and has_cli(tag):
            required.add("supivpn-cli")
        for name in required:
            a.require(f"{name} (= {version(tag)})" in fields.get("Depends", "").split(", "),
                      "Debian metapackage version mismatch")
