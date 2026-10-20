#!/usr/bin/env python3
# Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
# Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
# SPDX-License-Identifier: AGPL-3.0-only
"""Only plain documentation changes may omit executable checks on a PR."""
import os
from pathlib import PurePosixPath
import re
import subprocess


def code_required(event, files):
    if event != "pull_request" or not files:
        return True
    return any(not (PurePosixPath(path).suffix == ".md"
                    and ("/" not in path or path.startswith("docs/"))
                    and path not in {"THIRD_PARTY_NOTICES.md", "COPYRIGHT.md"}) for path in files)


def main():
    event = os.environ.get("GITHUB_EVENT_NAME", "")
    files = []
    if event == "pull_request":
        base, head = os.environ.get("BASE_SHA", ""), os.environ.get("HEAD_SHA", "")
        if not all(re.fullmatch("[0-9a-f]{40}", sha) for sha in (base, head)):
            raise ValueError("Missing full pull request commit IDs")
        result = subprocess.run(["git", "diff", "--name-only", "-z", base + "..." + head, "--"],
                                check=True, capture_output=True, timeout=30)
        files = [p for p in result.stdout.decode("utf-8").split("\0") if p]
    required = code_required(event, files)
    with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as stream:
        stream.write("code=" + str(required).lower() + "\n")
    print("Full executable checks required" if required else "Documentation checks only")


if __name__ == "__main__":
    main()
