#!/usr/bin/env python3
# Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
# Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
# SPDX-License-Identifier: AGPL-3.0-only
"""Package exact Git source and vendored Go dependencies for public distribution."""
import gzip
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile

import artifacts as a
import repository_audit


def command(root, args, timeout=120):
    result = subprocess.run(args, cwd=root, capture_output=True, timeout=timeout, check=True,
                            env=dict(os.environ, GIT_NO_REPLACE_OBJECTS="1", GOWORK="off", GOTOOLCHAIN="local",
                                     GOPATH=str(root / "local/go"), GOCACHE=str(root / "local/build-cache")))
    return result.stdout


def source_files(root, commit, *, require_checkout=True):
    a.require(a.COMMIT.fullmatch(commit), "Full source commit required")
    if require_checkout:
        a.require(command(root, ["git", "rev-parse", "HEAD"]).decode().strip() == commit,
                  "Source archive requires the checked-out commit")
        a.require(not command(root, ["git", "diff", "--name-only", "HEAD", "--"]),
                  "Source archive requires unchanged tracked files")
    result = {}
    for row in command(root, ["git", "ls-tree", "-rz", commit]).split(b"\0"):
        if not row:
            continue
        meta, name = row.split(b"\t", 1)
        mode, kind, oid = meta.decode().split()
        path = name.decode("utf-8")
        relative = Path(path)
        a.require(kind == "blob" and mode in {"100644", "100755"}
                  and not repository_audit.excluded(relative)
                  and repository_audit.permitted(relative), "Unreviewed source path/type")
        raw = command(root, ["git", "cat-file", "blob", oid])
        a.require(len(raw) <= repository_audit.MAX_BYTES and b"\0" not in raw,
                  "Binary or oversized source file")
        a.require(not repository_audit.findings(raw.decode("utf-8"), relative=path),
                  "Source secret-pattern review required")
        result[path] = (raw, int(mode, 8) & 0o777)
    a.require({"LICENSE", "COPYRIGHT.md", "go.mod", "go.sum", "Makefile"} <= result.keys(),
              "Source archive lacks build/license files")
    a.require(b"GNU AFFERO GENERAL PUBLIC LICENSE" in result["LICENSE"][0], "AGPL source required")
    return result


def add_tree(files, source, prefix):
    for path in sorted(source.rglob("*")):
        a.require(not path.is_symlink(), "Dependency source symlink refused")
        if path.is_file():
            name = prefix + path.relative_to(source).as_posix()
            a.require(name not in files, "Duplicate source member")
            files[name] = (a.regular(path, 16 * 1024 * 1024), 0o644)


def pack(root, commit, output):
    files = source_files(root, commit)
    local = root / "local"
    local.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="corresponding-source-", dir=local) as directory:
        vendor = Path(directory) / "vendor"
        command(root, ["go", "mod", "vendor", "-o", str(vendor)], timeout=300)
        add_tree(files, vendor, "vendor/")
    a.require(not command(root, ["git", "diff", "--name-only", "HEAD", "--"]),
              "Vendoring changed tracked source")
    goroot = Path(command(root, ["go", "env", "GOROOT"]).decode().strip()).resolve(strict=True)
    license_path = goroot / "LICENSE"
    # Homebrew installs the package license beside the libexec SDK directory.
    if not license_path.is_file() and goroot.name == "libexec":
        license_path = goroot.parent / "LICENSE"
    a.require(license_path.is_file(), "Go toolchain license is unavailable")
    files["third-party/go/LICENSE"] = (a.regular(license_path), 0o644)
    notices = [goroot / "PATENTS"]
    for path in (goroot / "src").rglob("*"):
        if path.name in {"LICENSE", "LICENSE.txt", "NOTICE", "COPYING", "PATENTS"} and path.is_file():
            notices.append(path)
    for path in sorted(set(notices)):
        if path.is_file():
            files["third-party/go/" + path.relative_to(goroot).as_posix()] = (a.regular(path), 0o644)
    metadata = {"format": 1, "commit": commit, "license": "AGPL-3.0-only",
                "go_version": command(root, ["go", "version"]).decode().strip(),
                "files": {name: a.sha(raw) for name, (raw, _) in sorted(files.items())}}
    files["SOURCE.json"] = ((json.dumps(metadata, sort_keys=True, indent=2) + "\n").encode(), 0o644)
    a.require(sum(len(raw) for raw, _ in files.values()) <= a.MAX_BUNDLE, "Source archive too large")
    output.mkdir(parents=True, exist_ok=True)
    target = output / ("supivpn-source-" + commit + ".tar.gz")
    with target.open("xb") as stream:
        with gzip.GzipFile(fileobj=stream, filename="", mtime=0, mode="wb") as zipped:
            with tarfile.open(fileobj=zipped, mode="w", format=tarfile.PAX_FORMAT) as archive:
                for name, (raw, mode) in sorted(files.items()):
                    info = tarfile.TarInfo("supivpn/" + name)
                    info.size, info.mode = len(raw), mode
                    archive.addfile(info, io.BytesIO(raw))
    return target, a.sha(a.regular(target, a.MAX_BUNDLE))


def verify(data, digest, commit, expected):
    """Inspect without extracting or executing downloaded source."""
    a.require(len(data) <= a.MAX_BUNDLE and a.sha(data) == digest, "Source archive digest mismatch")
    files = {}
    total = 0
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
        for member in archive:
            parts = member.name.split("/")
            a.require(parts[0] == "supivpn" and len(parts) > 1
                      and all(part not in {"", ".", ".."} for part in parts)
                      and "\\" not in member.name and member.isfile() and not member.issparse()
                      and set(member.pax_headers) <= {"path"} and member.mode in {0o644, 0o755}, "Unsafe source member")
            name = "/".join(parts[1:])
            a.require(name not in files and len(files) < 10000 and 0 <= member.size <= 16 * 1024 * 1024,
                      "Source archive limits exceeded")
            total += member.size
            a.require(total <= a.MAX_BUNDLE, "Expanded source archive too large")
            raw = archive.extractfile(member).read(member.size + 1)
            a.require(len(raw) == member.size, "Truncated source archive member")
            files[name] = raw
    a.require("SOURCE.json" in files and len(files["SOURCE.json"]) < 2 * 1024 * 1024, "Source manifest missing")
    metadata = a.json_object(files.pop("SOURCE.json"))
    a.require(metadata.get("format") == 1 and metadata.get("commit") == commit
              and metadata.get("license") == "AGPL-3.0-only"
              and metadata.get("files") == {name: a.sha(raw) for name, raw in files.items()},
              "Source manifest mismatch")
    originals = {name: raw for name, raw in files.items()
                 if not name.startswith(("vendor/", "third-party/go/"))}
    a.require(originals == {name: raw for name, (raw, _) in expected.items()}, "Source differs from signed tag")
    a.require("vendor/modules.txt" in files and "third-party/go/LICENSE" in files,
              "Dependency source or toolchain notices missing")
    return metadata
