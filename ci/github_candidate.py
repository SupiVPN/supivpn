#!/usr/bin/env python3
# Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
# Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
# SPDX-License-Identifier: AGPL-3.0-only
"""Authenticate a release tag and package its native build without remote writes."""
import json
import os
from pathlib import Path
import sys
import subprocess

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import artifacts as a
import source_archive
import github_release
import tag_release


def validate_context(env):
    ref = env.get("GITHUB_REF", "")
    version = ref.removeprefix("refs/tags/")
    a.require(env.get("GITHUB_REPOSITORY") == "SupiVPN/supivpn"
              and env.get("GITHUB_EVENT_NAME") == "push"
              and ref.startswith("refs/tags/") and len(version) <= 64
              and tag_release.VERSION.fullmatch(version), "Canonical version tag push required")
    commit = env.get("GITHUB_SHA", "")
    a.require(a.COMMIT.fullmatch(commit) and commit != "0" * 40, "Full candidate commit required")
    a.require(all(env.get(key, "").isdecimal() and int(env[key]) > 0
                  for key in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT")), "Run identity required")
    return commit, version


def verify_tag():
    commit, version = validate_context(os.environ)
    github_release.configure_origin()
    with github_release.public_keyring():
        actual, oid = github_release.release_identity.release_identity(version)
    a.require(actual == commit, "Signed tag differs from this workflow commit")
    with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as stream:
        stream.write("tag_oid=" + oid + "\n")
    print("Authenticated signed release tag " + version + " at " + commit)


def main():
    commit, version = validate_context(os.environ)
    arch = a.architecture(os.environ.get("ARCH", ""))
    oid = os.environ.get("SUPIVPN_TAG_OID", "")
    a.require(a.COMMIT.fullmatch(oid) and oid != "0" * 40, "Authenticated tag object required")
    output = ROOT / "out/github" / arch
    archive, digest = a.package(ROOT, version, commit, output, arch=arch)
    record = {"format": 2, "repository": "SupiVPN/supivpn", "commit": commit,
              "version": version, "tag": oid,
              "arch": arch, "run_id": int(os.environ["GITHUB_RUN_ID"]),
              "run_attempt": int(os.environ["GITHUB_RUN_ATTEMPT"]),
              "filename": archive.name, "sha256": digest}
    if arch == "arm64":
        source, source_digest = source_archive.pack(ROOT, commit, output)
        record["source"] = {"filename": source.name, "sha256": source_digest}
    with (output / "candidate.json").open("x", encoding="utf-8") as stream:
        json.dump(record, stream, sort_keys=True, indent=2)
        stream.write("\n")
    print("Prepared " + arch + " candidate for " + commit)


if __name__ == "__main__":
    try:
        if sys.argv[1:] == ["verify-tag"]:
            verify_tag()
        elif not sys.argv[1:]:
            main()
        else:
            raise ValueError("Unexpected arguments")
    except (OSError, ValueError, subprocess.SubprocessError,
            tag_release.TagError, tag_release.signatures.VerificationError):
        sys.exit("Candidate preparation refused; inspect source/build identity")
