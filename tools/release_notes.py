#!/usr/bin/env python3
# Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
# Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
# SPDX-License-Identifier: AGPL-3.0-only
"""Generate release notes from Git history and read them from signed tags."""
import argparse
from pathlib import Path
import re
import html
import os
import subprocess
import sys

from artifacts import regular

ROOT = Path(__file__).resolve().parents[1]
NUMBER = r"(?:0|[1-9][0-9]*)"
VERSION = re.compile(rf"v{NUMBER}\.{NUMBER}\.{NUMBER}(?:-(?:alpha|beta|rc)\.{NUMBER})?")
MAX_NOTES = 32768
MAX_TAG = MAX_NOTES + 16384
COMMIT = re.compile(r"[a-f0-9]{40}")
WEB = "https://github.com/SupiVPN/supivpn"


def notes_path(version):
    if len(version) > 64 or not VERSION.fullmatch(version):
        raise ValueError("Release notes require a supported release version")
    return Path("docs/releases") / (version + ".md")


def validate(version, text, *, allow_commit_subjects=False):
    notes_path(version)
    if (len(text.encode("utf-8")) > MAX_NOTES
            or not text.startswith("# SupiVPN " + version + "\n")
            or any(ord(c) < 32 and c not in "\n\t" for c in text)
            or (not allow_commit_subjects and re.search(r"\b(?:TODO|TBD|FIXME)\b", text, re.IGNORECASE))):
        raise ValueError("Release notes have an invalid title, size or placeholder")
    for heading in ("Changes", "Compatibility"):
        sections = re.findall(r"^## " + heading + r"\n(.*?)(?=^## |\Z)",
                              text, re.MULTILINE | re.DOTALL)
        if len(sections) != 1 or len(sections[0].strip()) < 20:
            raise ValueError("Release notes need substantive Changes and Compatibility sections")
    return text.strip() + "\n"


def version_order(version):
    notes_path(version)
    core, separator, suffix = version[1:].partition("-")
    numbers = tuple(int(part) for part in core.split("."))
    if not separator:
        return (*numbers, 3, 0)
    stage, number = suffix.split(".")
    return (*numbers, {"alpha": 0, "beta": 1, "rc": 2}[stage], int(number))


def tag_message(raw, version, commit=None):
    """Parse an annotated OpenPGP tag; callers must verify its GPG signature."""
    notes_path(version)
    if len(raw.encode("utf-8")) > MAX_TAG:
        raise ValueError("Oversized release tag")
    header, separator, body = raw.partition("\n\n")
    rows = header.splitlines()
    if (not separator or len(rows) != 4 or not rows[0].startswith("object ")
            or not COMMIT.fullmatch(rows[0][7:]) or rows[0][7:] == "0" * 40
            or rows[1] != "type commit" or rows[2] != "tag " + version
            or not rows[3].startswith("tagger ")
            or (commit is not None and rows[0][7:] != commit)):
        raise ValueError("Release tag identity mismatch")
    marker = "-----BEGIN PGP SIGNATURE-----\n"
    if (body.count(marker) != 1 or body.count("-----END PGP SIGNATURE-----") != 1
            or not body.endswith("-----END PGP SIGNATURE-----\n")):
        raise ValueError("Missing or ambiguous release tag signature")
    message, signature = body.split(marker, 1)
    if not message.endswith("\n") or not signature.strip():
        raise ValueError("Invalid release tag message boundary")
    return rows[0][7:], message


def generate(version, commit, history, previous=None):
    """Render commit subjects as inert text; never infer compatibility from them."""
    notes_path(version)
    if not COMMIT.fullmatch(commit) or commit == "0" * 40:
        raise ValueError("Invalid release commit")
    lines = history.splitlines()
    if len(history.encode("utf-8")) > 1024 * 1024 or len(lines) > 256:
        raise ValueError("Release history is too large")
    changes = []
    seen = set()
    for line in lines:
        sha, separator, subject = line.partition("\t")
        if (not separator or not COMMIT.fullmatch(sha) or sha == "0" * 40 or sha in seen
                or not subject.strip() or len(subject) > 1024
                or any(ord(c) < 32 or ord(c) == 127 for c in subject)):
            raise ValueError("Invalid release history record")
        seen.add(sha)
        subject = html.escape(subject, quote=True)
        subject = re.sub(r"([\\`*_{}\[\]()#+.!|~-])", r"\\\1", subject).replace("@", "&#64;")
        commit_path = "/commit/"
        changes.append("- " + subject + " ([" + sha[:12] + "](" + WEB + commit_path + sha + "))")
    if previous is None:
        introduction = "Changes through commit `" + commit + "`."
        if not changes:
            raise ValueError("Initial release history is empty")
    else:
        notes_path(previous)
        tag_path = "/releases/tag/"
        introduction = "Changes since [" + previous + "](" + WEB + tag_path + previous + ")."
        if not changes:
            changes.append("- No source changes since " + previous + "; this tag promotes the same commit.")
    return validate(version, "# SupiVPN " + version + "\n\n" + introduction
                    + "\n\n## Changes\n\n" + "\n".join(changes)
                    + "\n\n## Compatibility\n\n"
                    + "These notes summarize commit subjects; they do not assert runtime or migration compatibility. "
                    + "Review configuration and migration changes before upgrading. "
                    + "The Release page reports schema compatibility from the verified package manifests.\n",
                    allow_commit_subjects=True)


def git_tag(root, version):
    """Read locally after CI's signature gate; do not fetch or mutate refs."""
    notes_path(version)
    try:
        result = subprocess.run(
            ["git", "-c", "safe.directory=", "-c", "safe.directory=" + str(root.resolve()),
             "-c", "core.fsmonitor=false", "cat-file", "tag", "refs/tags/" + version],
            cwd=root, env=dict(os.environ, GIT_NO_REPLACE_OBJECTS="1"),
            capture_output=True, text=True, errors="strict", timeout=15,
        )
    except (OSError, subprocess.SubprocessError, UnicodeError):
        raise ValueError("Cannot read local release tag") from None
    if result.returncode or len(result.stdout.encode("utf-8")) > MAX_TAG:
        raise ValueError("Cannot read local release tag")
    return result.stdout


def load_tag(root, version, commit):
    if not COMMIT.fullmatch(commit) or commit == "0" * 40:
        raise ValueError("Release notes require the verified commit SHA")
    _, message = tag_message(git_tag(root, version), version, commit)
    return validate(version, message, allow_commit_subjects=True)


def load(root, version):
    return validate(version, regular(root / notes_path(version), MAX_NOTES).decode("utf-8"))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_mutually_exclusive_group(required=True)
    actions.add_argument("--version")
    actions.add_argument("--audit", action="store_true")
    actions.add_argument("--tag")
    parser.add_argument("--commit", default="")
    args = parser.parse_args()
    try:
        if args.tag:
            load_tag(ROOT, args.tag, args.commit)
            print("Signed-tag release notes verified")
            return 0
        if args.commit:
            raise ValueError("--commit requires --tag")
        versions = ([args.version] if args.version else
                    [path.stem for path in (ROOT / "docs/releases").iterdir() if path.name != "README.md"])
        # Notes normally live in signed tags; checked-in note files are optional.
        for version in versions:
            load(ROOT, version)
    except (OSError, ValueError):
        print("Release notes refused; use make tag to embed notes in a signed tag, or check the historical notes file",
              file=sys.stderr)
        return 1
    print(f"Release note files verified: {len(versions)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
