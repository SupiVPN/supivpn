#!/usr/bin/env python3
# Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
# Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
# SPDX-License-Identifier: AGPL-3.0-only
"""Authenticate release tags and their source payloads."""
import os
from pathlib import Path
import subprocess

import artifacts as a
import tag_release as tag

def check_checkout():
    a.require(Path(tag.git(["rev-parse", "--show-toplevel"], "repository check").stdout.strip()).resolve() == tag.ROOT,
              "Run from the SupiVPN product checkout")
    a.require(tag.git(["remote", "get-url", "--all", "origin"], "origin check").stdout.splitlines() == [tag.ORIGIN],
              "origin must use the canonical SupiVPN repository URL")


def release_identity(version):
    a.require(len(version) <= 64 and tag.VERSION.fullmatch(version),
              "VERSION must be vMAJOR.MINOR.PATCH, optionally followed by -alpha.N, -beta.N or -rc.N")
    check_checkout()
    current = tag.signatures.read_policy(tag.ROOT / "ci/signers.json")
    ref = "refs/tags/" + version
    result = tag.git(["ls-remote", "--exit-code", "--refs", "origin", ref, "refs/heads/main"],
                     "remote release lookup", timeout=60)
    refs = {}
    for line in result.stdout.splitlines():
        fields = line.split()
        a.require(len(fields) == 2 and tag.COMMIT.fullmatch(fields[0]) and fields[0] != "0" * 40
                  and fields[1] in {ref, "refs/heads/main"} and fields[1] not in refs,
                  "Unexpected remote release refs")
        refs[fields[1]] = fields[0]
    a.require(set(refs) == {ref, "refs/heads/main"}, "Release tag or main is missing on origin")
    oid, main = refs[ref], refs["refs/heads/main"]
    # Fetch immutable object IDs without changing branches, local tags or FETCH_HEAD.
    tag.git(["fetch", "--no-tags", "--no-write-fetch-head", "--refmap=", "origin", oid, main],
            "release object fetch", timeout=120)
    a.require(tag.git(["cat-file", "-t", oid], "tag object check").stdout.strip() == "tag",
              "Release must use a signed annotated tag")
    tag.verify_signature("verify-tag", oid, (current,), "release_signers")
    raw = tag.git(["cat-file", "tag", oid], "signed tag identity").stdout
    a.require(len(raw) <= 65536, "Oversized release tag")
    headers = raw.split("\n\n", 1)[0].splitlines()
    a.require(len(headers) >= 3 and headers[0].startswith("object ") and headers[1] == "type commit"
              and headers[2] == "tag " + version, "Signed tag name or target type mismatch")
    commit = headers[0][7:]
    a.identity(version, commit)
    a.require(tag.git(["cat-file", "-t", commit], "commit object check").stdout.strip() == "commit",
              "Release target is not a commit")
    target = tag.signatures.parse_policy(tag.git(["show", commit + ":ci/signers.json"],
                                                 "release signer policy").stdout)
    policies = (current, target)
    tag.verify_signature("verify-tag", oid, policies, "release_signers")
    tag.git(["merge-base", "--is-ancestor", commit, main], "release membership in main")
    return commit, oid


def release_sources(commit):
    # Compare the non-binary payload with the authenticated source history.
    names = {name: a.source_path(name) for name in a.FIXED if name not in a.BUILT_FILES}
    directory = "internal/postgres/migrations"
    migrations = tag.git(["ls-tree", "-r", "--name-only", commit, directory],
                         "release migration list").stdout.splitlines()
    mapped = {"migrations/" + name.removeprefix(directory + "/"): name for name in migrations}
    a.require(0 < len(mapped) < a.MAX_FILES and len(mapped) == len(migrations) and
              all(a.MIGRATION.fullmatch(name) for name in mapped), "Unexpected release migrations")
    names.update(mapped)
    result = {}
    for name in sorted(names):
        # Resolve only allowlisted paths, then read the exact blob bytes.
        blob = tag.git(["rev-parse", commit + ":" + names[name]], "release source object").stdout.strip()
        a.require(bool(tag.COMMIT.fullmatch(blob)), "Invalid release source object")
        result[name] = git_blob(blob)
    return result


def git_blob(oid):
    # tag.git uses text mode; blob bytes must retain their original line endings.
    size = tag.git(["cat-file", "-s", oid], "release source size").stdout.strip()
    a.require(size.isdecimal() and int(size) <= a.MAX_FILE, "Oversized release source")
    run = subprocess.run(
        ["git", "cat-file", "blob", oid], cwd=tag.ROOT,
        env=dict(os.environ, GIT_NO_REPLACE_OBJECTS="1"), capture_output=True, timeout=30,
    )
    a.require(run.returncode == 0 and len(run.stdout) <= a.MAX_FILE, "Release source read failed")
    return run.stdout
