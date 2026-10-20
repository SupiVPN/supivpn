#!/usr/bin/env python3
# Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
# Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
# SPDX-License-Identifier: AGPL-3.0-only
"""Create one local signed release tag; never push, publish, or deploy."""
import os
from pathlib import Path
import re
import subprocess
import sys

import release_notes
import signatures

ROOT = Path(__file__).resolve().parents[1]
NUMBER = r"(?:0|[1-9][0-9]*)"
VERSION = re.compile(rf"v{NUMBER}\.{NUMBER}\.{NUMBER}(?:-(?:alpha|beta|rc)\.{NUMBER})?")
COMMIT = re.compile(r"[a-f0-9]{40}")
ORIGIN = "git@github.com:SupiVPN/supivpn.git"
GITHUB_ORIGINS = {"git@github.com:SupiVPN/supivpn.git", "https://github.com/SupiVPN/supivpn.git",
                  "https://github.com/SupiVPN/supivpn"}


class TagError(Exception):
    """Fixed diagnostics without raw Git/GPG output or credentials."""


def require(condition, message):
    if not condition:
        raise TagError(message)


def git(args, stage, allowed=(0,), timeout=30, input=None):
    env = dict(os.environ, GIT_TERMINAL_PROMPT="0", GIT_NO_REPLACE_OBJECTS="1")
    if args[:2] == ["tag", "-s"]:
        env.update(GIT_COMMITTER_NAME="SupiVPN Releases", GIT_COMMITTER_EMAIL="release@supivpn.com")
    try:
        result = subprocess.run(
            ["git", "-c", "gpg.format=openpgp", "-c", "gpg.program=gpg",
             "-c", "gpg.openpgp.program=gpg", "-c", "core.fsmonitor=false", *args],
            cwd=ROOT, env=env, capture_output=True, text=True, errors="replace", timeout=timeout, input=input,
        )
    except (OSError, subprocess.SubprocessError):
        raise TagError(stage + " failed or timed out") from None
    require(result.returncode in allowed, stage + " failed")
    return result


def verify_signature(kind, ref, policies, field):
    result = git([kind, "--raw", ref], kind)
    require(all(signatures.valid_signature(result.stderr, policy[field], policy["tag_signing_subkeys"])
                for policy in policies),
            kind + " does not satisfy the current and target commit signer policies")


def automatic_notes(version, commit, policies):
    """Pin a signed ancestor tag, then summarize its exact commit range."""
    result = git(["ls-remote", "--tags", "--refs", "origin", "refs/tags/v*"],
                 "release history tags", timeout=60)
    require(len(result.stdout) <= 1024 * 1024, "Release tag list is too large")
    versions = {}
    for line in result.stdout.splitlines():
        fields = line.split()
        require(len(fields) == 2 and COMMIT.fullmatch(fields[0]) and fields[0] != "0" * 40
                and fields[1].startswith("refs/tags/"), "Invalid remote release tag record")
        name = fields[1].removeprefix("refs/tags/")
        if len(name) > 64 or not VERSION.fullmatch(name):
            continue
        require(name not in versions, "Duplicate remote release tag")
        if release_notes.version_order(name) < release_notes.version_order(version):
            versions[name] = fields[0]
    require(len(versions) <= 512, "Too many release tags to select a baseline")
    previous = None
    revision = commit
    for name in sorted(versions, key=release_notes.version_order, reverse=True):
        oid = versions[name]
        git(["fetch", "--no-tags", "--no-write-fetch-head", "--refmap=", "origin", oid],
            "release baseline fetch", timeout=60)
        raw = git(["cat-file", "tag", oid], "release baseline tag check").stdout
        try:
            base, _ = release_notes.tag_message(raw, name)
        except ValueError:
            raise TagError("Release baseline must be an annotated OpenPGP tag") from None
        ancestor = git(["merge-base", "--is-ancestor", base, commit],
                       "release baseline ancestry", allowed=(0, 1))
        if ancestor.returncode:
            continue
        verify_signature("verify-tag", oid, policies, "release_signers")
        previous = name
        revision = base + ".." + commit
        break
    history = git(["log", "--no-show-signature", "--no-decorate", "--format=%H%x09%s",
                   "--reverse", "--max-count=257", revision, "--"], "release commit history").stdout
    try:
        return release_notes.generate(version, commit, history, previous)
    except ValueError:
        raise TagError("Cannot generate bounded release notes from the selected Git history; no tag was created") from None


def create_tag(version, commit):
    require(len(version) <= 64 and VERSION.fullmatch(version),
            "VERSION must be vMAJOR.MINOR.PATCH, optionally followed by -alpha.N, -beta.N or -rc.N; no leading zeroes")
    require(commit == "main" or (COMMIT.fullmatch(commit) and commit != "0" * 40),
            "COMMIT must be main or a full lowercase 40-character commit SHA")
    require(not os.environ.get("CI") and not os.environ.get("GITHUB_ACTIONS"),
            "Run tag creation locally; CI must not hold a tag-signing private key")
    top = git(["rev-parse", "--show-toplevel"], "repository check").stdout.strip()
    require(Path(top).resolve() == ROOT, "Run from the SupiVPN product checkout")
    require(not git(["status", "--porcelain=v1", "--untracked-files=normal"], "clean checkout check").stdout,
            "Commit or resolve tracked/untracked changes before tagging; ignored local artifacts are allowed")
    for args in (["remote", "get-url", "--all", "origin"],
                 ["remote", "get-url", "--push", "--all", "origin"]):
        require(git(args, "origin check").stdout.splitlines() == [ORIGIN],
                "origin must use the canonical SupiVPN repository URL for both fetch and push")

    ref = "refs/tags/" + version
    local = git(["show-ref", "--verify", "--quiet", ref], "local tag check", allowed=(0, 1))
    require(local.returncode == 1, "Tag already exists locally; tags are never replaced")
    remote = git(["ls-remote", "--exit-code", "--refs", "origin", ref],
                 "remote tag check", allowed=(0, 2), timeout=60)
    require(remote.returncode == 2 and not remote.stdout, "Tag already exists on origin; choose a new version")
    git(["fetch", "--no-tags", "origin", "refs/heads/main"], "main fetch", timeout=60)
    main = git(["rev-parse", "--verify", "FETCH_HEAD^{commit}"], "main commit check").stdout.strip()
    require(COMMIT.fullmatch(main) and main != "0" * 40, "Fetched main must identify a full commit SHA")
    if commit == "main":
        commit = main
        print(f"Selected fetched main commit: {commit}", flush=True)
    require(git(["cat-file", "-t", commit], "commit object check").stdout.strip() == "commit",
            "COMMIT must identify a commit object, not a tag or other Git object")
    git(["merge-base", "--is-ancestor", commit, main], "commit membership in fetched main")

    current = signatures.read_policy(ROOT / "ci/signers.json")
    target = signatures.parse_policy(git(["show", f"{commit}:ci/signers.json"],
                                         "target signer policy check").stdout)
    policies = (current, target)
    choices = set(current["tag_signing_subkeys"]) & set(target["tag_signing_subkeys"])
    signing_key = os.environ.get("SUPIVPN_TAG_SIGNING_SUBKEY", "")
    if not signing_key and len(choices) == 1:
        signing_key = next(iter(choices))
    require(signing_key in choices,
            "Select an authorized tag subkey with SUPIVPN_TAG_SIGNING_SUBKEY")
    notes = automatic_notes(version, commit, policies)
    print(notes, flush=True)
    print(f"Creating local signed tag {version} at {commit}", flush=True)
    try:
        git(["tag", "-s", "-u", signing_key + "!", "--cleanup=verbatim", "-F", "-", "--", version, commit],
            "tag signing", timeout=180, input=notes)
        verify_signature("verify-tag", ref, policies, "release_signers")
        actual = git(["rev-parse", "--verify", ref + "^{commit}"], "tag target check").stdout.strip()
        require(actual == commit, "Signed tag does not point to the requested commit")
        raw = git(["cat-file", "tag", ref], "signed release notes check").stdout
        try:
            _, message = release_notes.tag_message(raw, version, commit)
            require(message == notes, "Signed release notes differ from the generated notes")
        except ValueError:
            raise TagError("Signed release notes are invalid") from None
    except TagError as error:
        raise TagError(str(error) + "; a local tag may exist: inspect it before retrying; nothing was pushed") from None
    print("Local tag and authorized GPG signature verified. Nothing was pushed.")
    print("After reviewing the tag and notes, push it explicitly to start its release checks:")
    print(f"git push origin {ref}")


def main():
    try:
        create_tag(os.environ.get("SUPIVPN_TAG_VERSION", ""), os.environ.get("SUPIVPN_TAG_COMMIT", "main"))
    except (TagError, signatures.VerificationError) as error:
        print("Tag creation stopped: " + str(error), file=sys.stderr)
        return 1
    except (OSError, ValueError):
        print("Tag creation stopped: local setup failed; inspect local tag status before retrying", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
