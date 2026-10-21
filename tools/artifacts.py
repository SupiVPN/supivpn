#!/usr/bin/env python3
# Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
# Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
# SPDX-License-Identifier: AGPL-3.0-only
"""Deterministic release bundles and bounded, verified extraction."""
import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import stat
import sys
import tarfile
import tempfile
import zipfile

VERSION = re.compile(r"v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-[a-z0-9]+(?:[.-][a-z0-9]+)*)?")
HEX = re.compile(r"[0-9a-f]{64}")
COMMIT = re.compile(r"[0-9a-f]{40}")
BINARIES = ("supivpn", "supivpn-controller", "supivpn-profile", "supivpn-migrate", "bootstrap", "bootstrap-agent", "bootstrap-recovery")
LAMBDA_ZIPS = {"supivpn-lambda.zip": "bootstrap", "supivpn-agent-lambda.zip": "bootstrap-agent",
               "supivpn-recovery-lambda.zip": "bootstrap-recovery"}
LAMBDA_COMPONENTS = {"public": "supivpn-lambda.zip", "agent": "supivpn-agent-lambda.zip",
                     "recovery": "supivpn-recovery-lambda.zip"}
ARTIFACTS = (*BINARIES, *LAMBDA_ZIPS)
FIXED = {"LICENSE", "THIRD_PARTY_NOTICES.md", "THIRD_PARTY_LICENSES.txt",
         "examples/client.ovpn.example", "release.json",
         *("bin/" + name for name in BINARIES), *("lambda/" + name for name in LAMBDA_ZIPS)}
MIGRATION = re.compile(r"migrations/[0-9]{3}_[a-z0-9_]+\.sql")
ARCHITECTURES = ("arm64", "amd64")
ELF_MACHINES = {"arm64": b"\xb7\x00", "amd64": b"\x3e\x00"}


def architecture(arch):
    require(arch in ARCHITECTURES, "Architecture must be arm64 or amd64")
    return arch


MAX_FILE = 96 * 1024 * 1024
MAX_BUNDLE = 256 * 1024 * 1024
MAX_FILES = 128


class ValidationError(ValueError):
    """A static validation reason; never include input values or file contents."""


def require(value, message):
    if not value:
        raise ValidationError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def checksums(assets):
    """Render the already validated asset names and digests in canonical order."""
    return "".join(digest + "  " + name + "\n" for name, digest in sorted(assets.items())).encode("ascii")


def identity(version, commit):
    require(VERSION.fullmatch(version) and COMMIT.fullmatch(commit), "Invalid version or commit")


def allowed(name):
    return name in FIXED or bool(MIGRATION.fullmatch(name))


def regular(path, limit=MAX_FILE):
    # Reject links in every component, including a substituted local/ directory.
    for part in (path, *path.parents):
        require(not part.is_symlink(), "Symlink input refused")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as handle:
        info = os.fstat(handle.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_size <= limit, "Invalid file size/type")
        data = handle.read(limit + 1)
    require(len(data) <= limit, "Oversized input")
    return data


def json_object(data):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "Duplicate JSON key")
            result[key] = value
        return result
    return json.loads(data, object_pairs_hook=unique)


def validate_payload(files, arch="arm64"):
    architecture(arch)
    require(FIXED <= files.keys() and all(allowed(name) for name in files), "Unexpected/missing bundle file")
    require(len(files) <= MAX_FILES and sum(map(len, files.values())) <= MAX_BUNDLE, "Bundle too large")
    release = json_object(files["release.json"])
    require(set(release) == {"format", "schema", "schema_digest", "compatible_schemas", "artifacts", "lambda_components"},
            "Unexpected release manifest fields")
    require(release.get("format") == 1 and type(release.get("schema")) is int, "Invalid release manifest")
    require(release["lambda_components"] == {
        component: {"artifact": artifact, "required_schema": release["schema"]}
        for component, artifact in LAMBDA_COMPONENTS.items()}, "Invalid Lambda component mapping")
    require(set(release.get("artifacts", {})) == set(ARTIFACTS), "Unexpected release artifact list")
    for name in ARTIFACTS:
        require(sha(files[artifact_path(name)]) == release["artifacts"][name], "Stale artifact digest")
    for name in BINARIES:
        data = files["bin/" + name]
        require(len(data) >= 20 and data[:6] == b"\x7fELF\x02\x01" and data[18:20] == ELF_MACHINES[arch],
                "Binary must be Linux ELF64 matching the requested architecture")
    migrations = sorted(name for name in files if MIGRATION.fullmatch(name))
    require(migrations and release["schema"] == len(migrations), "Migration count/schema mismatch")
    def digest(names):
        return sha("".join(Path(name).name + ":" + sha(files[name]) + "\n" for name in names).encode())
    require(digest(migrations) == release.get("schema_digest"), "Stale migration digest")
    compatible = release.get("compatible_schemas", {})
    require(isinstance(compatible, dict) and compatible.get(str(len(migrations))) == digest(migrations),
            "Missing current schema compatibility")
    for number, expected in compatible.items():
        require(number.isdecimal() and 1 <= int(number) <= len(migrations) and
                digest(migrations[:int(number)]) == expected, "Invalid schema compatibility")
    for name, binary in LAMBDA_ZIPS.items():
        with zipfile.ZipFile(io.BytesIO(files["lambda/" + name])) as archive:
            entries = archive.infolist()
            expected = {"bootstrap", "client.ovpn.template"} if binary == "bootstrap" else {"bootstrap"}
            require(len(entries) == len(expected) and {entry.filename for entry in entries} == expected,
                    "Lambda ZIP must contain only its component assets")
            for entry in entries:
                require(entry.file_size <= MAX_FILE and not entry.flag_bits & 1, "Invalid ZIP member")
            require(archive.read("bootstrap") == files["bin/" + binary], "Lambda binary mismatch")
            if binary == "bootstrap":
                require(archive.read("client.ovpn.template") == files["examples/client.ovpn.example"], "Lambda template mismatch")
    return release


def artifact_path(name):
    require(name in ARTIFACTS, "Unexpected artifact")
    return "lambda/" + name if name.endswith(".zip") else "bin/" + name


BUILT_FILES = frozenset({artifact_path(name) for name in ARTIFACTS} | {"release.json"})


def source_path(name, arch="arm64"):
    """Map format-3 archive paths to reviewed source/build inputs."""
    require(allowed(name), "Unexpected bundle path")
    architecture(arch)
    if name == "release.json":
        return "local/" + arch + "/release.json"
    if name.startswith(("bin/", "lambda/")):
        return "local/" + arch + "/" + name.split("/", 1)[1]
    if name.startswith("migrations/"):
        return "internal/postgres/" + name
    return name


def package(root, version, commit, output, *, bundle_layout=False, arch="arm64"):
    identity(version, commit)
    files = {name: regular(root / (name if bundle_layout else source_path(name, arch))) for name in FIXED}
    migrations = "migrations"
    for path in (root / (migrations if bundle_layout else "internal/postgres/migrations")).iterdir():
        name = migrations + "/" + path.name
        require(bool(MIGRATION.fullmatch(name)), "Unexpected migration file")
        files[name] = regular(path)
    validate_payload(files, arch)
    metadata = {"format": 3, "version": version, "commit": commit, "target": "linux-" + arch,
                "files": {name: {"sha256": sha(data), "size": len(data)} for name, data in sorted(files.items())}}
    files["bundle.json"] = (json.dumps(metadata, sort_keys=True, indent=2) + "\n").encode()
    output.mkdir(parents=True, exist_ok=True, mode=0o700)
    target = output / filename(version, arch)
    require(not target.exists(), "Version already packaged; use a fresh output directory")
    fd, pending = tempfile.mkstemp(prefix=".bundle-", dir=output)
    try:
        with os.fdopen(fd, "wb") as stream:
            with gzip.GzipFile(filename="", mode="wb", fileobj=stream, mtime=0) as zipped:
                with tarfile.open(fileobj=zipped, mode="w", format=tarfile.USTAR_FORMAT) as archive:
                    for name, data in sorted(files.items()):
                        info = tarfile.TarInfo(name)
                        info.size = len(data)
                        info.mode = 0o755 if name in {"bin/" + x for x in BINARIES} else 0o644
                        archive.addfile(info, io.BytesIO(data))
        digest = sha(regular(Path(pending), MAX_BUNDLE))
        # Exclusive publication; never overwrite an existing version.
        os.link(pending, target)
        with (output / "SHA256SUMS").open("xb") as handle:
            handle.write(checksums({target.name: digest}))
        return target, digest
    finally:
        os.unlink(pending)


def filename(version, arch="arm64"):
    architecture(arch)
    require(bool(VERSION.fullmatch(version)), "Invalid version")
    return "supivpn-" + version + "-linux-" + arch + ".tar.gz"


def unpack(data, expected, version, commit, cache, expected_sources=None, *, arch="arm64"):
    architecture(arch)
    identity(version, commit)
    require(bool(HEX.fullmatch(expected)) and len(data) <= MAX_BUNDLE and sha(data) == expected,
            "Bundle checksum mismatch")
    files = {}
    total = 0
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
        for member in archive:
            require(member.name not in files and member.isfile() and not member.issparse() and
                    not member.pax_headers and
                    (member.name == "bundle.json" or allowed(member.name)),
                    "Unsafe/duplicate archive member")
            require(0 <= member.size <= MAX_FILE and len(files) < MAX_FILES, "Archive limit exceeded")
            total += member.size
            require(total <= MAX_BUNDLE, "Expanded archive too large")
            files[member.name] = archive.extractfile(member).read(member.size + 1)
            require(len(files[member.name]) == member.size, "Truncated member")
    require("bundle.json" in files and len(files["bundle.json"]) <= 65536, "Missing/oversized bundle manifest")
    meta = json_object(files["bundle.json"])
    require(type(meta.get("format")) is int and meta["format"] == 3 and
            meta.get("version") == version and meta.get("commit") == commit and
            meta.get("target") == "linux-" + arch, "Bundle identity mismatch")
    payload = {name: value for name, value in files.items() if name != "bundle.json"}
    require(set(meta.get("files", {})) == set(payload), "Bundle file set mismatch")
    for name, value in payload.items():
        require(meta["files"][name] == {"sha256": sha(value), "size": len(value)}, "Member checksum mismatch")
    validate_payload(payload, arch)
    if expected_sources is not None:
        sources = {name: value for name, value in payload.items() if name not in BUILT_FILES}
        require(sources == expected_sources, "Bundle sources differ from the signed release commit")
    cache.mkdir(parents=True, exist_ok=True, mode=0o700)
    require(not any(part.is_symlink() for part in (cache, *cache.parents)), "Cache must not use symlinks")
    info = cache.stat()
    require(info.st_uid == os.getuid() and not info.st_mode & 0o077,
            "Cache must be owned by the current user and mode 0700")
    dest = cache / (version + "-" + expected)
    if dest.exists() or dest.is_symlink():
        require(dest.is_dir() and not dest.is_symlink(), "Invalid cache entry")
        actual = {f.relative_to(dest).as_posix() for f in dest.rglob("*") if not f.is_dir() or f.is_symlink()}
        require(actual == set(files), "Existing cache has unexpected files")
        for name, value in files.items():
            require(regular(dest / name) == value, "Existing cache modified")
        return dest
    executable_paths = {"bin/" + name for name in BINARIES}
    temporary = Path(tempfile.mkdtemp(prefix=".unpack-", dir=cache))
    try:
        for name, value in files.items():
            path = temporary / name
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("xb") as handle:
                handle.write(value)
            path.chmod(0o755 if name in executable_paths else 0o644)
        # A digest-addressed cache is immutable; concurrent operations fail closed.
        temporary.rename(dest)
        return dest
    finally:
        if temporary.exists():
            shutil.rmtree(temporary)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("version")
    parser.add_argument("commit")
    parser.add_argument("--arch", choices=ARCHITECTURES, default="arm64")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        target, digest = package(Path(__file__).resolve().parents[1], args.version,
                                 args.commit, args.output, arch=args.arch)
        print(digest + "  " + target.name)
    except (OSError, ValueError, KeyError, TypeError, zipfile.BadZipFile):
        print("Bundle creation refused; check inputs and integrity", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
