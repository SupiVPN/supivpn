#!/usr/bin/env python3
# Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
# Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
# SPDX-License-Identifier: AGPL-3.0-only
"""Skip executable checks only for a verified documentation-only PR or main push."""
import os
from pathlib import PurePosixPath
import re
import subprocess


def code_required(event, files):
    if event not in {"pull_request", "push"} or not files:
        return True
    return any(not (PurePosixPath(path).suffix == ".md"
                    and ("/" not in path or path.startswith("docs/"))
                    and path not in {"THIRD_PARTY_NOTICES.md", "COPYRIGHT.md"}) for path in files)


def git(*args):
    return subprocess.run(["git", *args], check=True, capture_output=True, timeout=30).stdout


def scope(env):
    event = env.get("GITHUB_EVENT_NAME", "")
    if event == "pull_request":
        base, head = env.get("BASE_SHA", ""), env.get("HEAD_SHA", "")
    elif (event == "push" and env.get("GITHUB_REF") == "refs/heads/main"
          and env.get("PUSH_FORCED") == "false"):
        base, head = env.get("BEFORE_SHA", ""), env.get("AFTER_SHA", "")
        if head != env.get("GITHUB_SHA"):
            return True, "", ""
    else:
        # Tags, schedules, manual runs and unknown events always run everything.
        return True, "", ""
    if not all(re.fullmatch("[0-9a-f]{40}", sha) and sha != "0" * 40 for sha in (base, head)):
        return True, "", ""
    try:
        if event == "pull_request":
            base = git("merge-base", base, head).decode("ascii").strip()
            if not re.fullmatch("[0-9a-f]{40}", base):
                return True, "", ""
        else:
            git("merge-base", "--is-ancestor", base, head)
        # Include both sides of renames: a source file moved to docs is still code.
        raw = git("diff", "--no-ext-diff", "--no-renames", "--name-only", "-z", base, head, "--")
        files = [path for path in raw.decode("utf-8").split("\0") if path]
    except (OSError, subprocess.SubprocessError, UnicodeError):
        return True, "", ""
    return code_required(event, files), base, head


def main():
    required, base, head = scope(os.environ)
    with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as stream:
        stream.write("code=" + str(required).lower() + "\n")
        stream.write("base=" + base + "\nhead=" + head + "\n")
    print("Full executable checks required" if required else "Documentation checks only")


if __name__ == "__main__":
    main()
