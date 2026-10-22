#!/usr/bin/env python3
# Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
# SPDX-License-Identifier: AGPL-3.0-only
"""Build and retain tested Debian candidates for an authenticated tag push."""
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import artifacts as a
import debian_packages
import debian_release as deb
import github_candidate
import source_archive


def retain(work, output, arch, commit, version, oid, env):
    names = deb.filenames(version, arch)
    a.require({p.name for p in work.glob("*.deb")} == {n for n in names if n.endswith(".deb")},
              "Unexpected Debian binary output set")
    output.mkdir(parents=True, exist_ok=False)
    assets = {}
    for name in sorted(names):
        raw = a.regular(work / name, a.MAX_BUNDLE)
        (output / name).write_bytes(raw)
        assets[name] = a.sha(raw)
    record = {"format": 1, "repository": "SupiVPN/supivpn", "commit": commit, "version": version,
              "tag": oid, "arch": arch, "run_id": int(env["GITHUB_RUN_ID"]),
              "run_attempt": int(env["GITHUB_RUN_ATTEMPT"]), "assets": assets}
    (output / "candidate.json").write_text(json.dumps(record, sort_keys=True, indent=2) + "\n")


def main():
    commit, version = github_candidate.validate_context(os.environ)
    arch = a.architecture(os.environ.get("ARCH", ""))
    oid = os.environ.get("SUPIVPN_TAG_OID", "")
    a.require(a.COMMIT.fullmatch(oid) and oid != "0" * 40, "Authenticated tag object required")
    originals = source_archive.source_files(ROOT, commit)
    epoch = deb.commit_epoch(ROOT, commit)
    work = debian_packages.build(ROOT, arch, "go", "docker", test=True, version=version, epoch=epoch)
    # Auditing permits local source files; a release must contain only tagged inputs.
    inputs = json.loads((work / "input-sha256.json").read_text())
    a.require(inputs == {name: a.sha(raw) for name, (raw, _) in originals.items()},
              "Debian build inputs differ from signed tag")
    deb.verify_source((work / f"supivpn_{deb.version(version)}.tar.xz").read_bytes(),
                      (work / f"supivpn_{deb.version(version)}.dsc").read_bytes(), version, originals, epoch)
    for path in work.glob("*.deb"):
        deb.verify_package(path, version, arch)
    retain(work, ROOT / "out/debian" / arch, arch, commit, version, oid, os.environ)


if __name__ == "__main__":
    main()
