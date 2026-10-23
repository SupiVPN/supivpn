#!/usr/bin/env python3
# Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
# Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
# SPDX-License-Identifier: AGPL-3.0-only
"""Check repository language without executing code or printing file contents."""
import argparse
import json
import os
from pathlib import Path
import re
import stat
import sys

FORBIDDEN = re.compile(
    r"[\u0400-\u052f\u1c80-\u1c8f\u2de0-\u2dff\uA640-\uA69f"
    r"\uFE2E-\uFE2F\U0001E030-\U0001E08F"
    r"\u2E80-\u2FDF\u3005-\u3007\u3021-\u3029\u3038-\u303B"
    r"\u3100-\u312F\u31A0-\u31EF\u3400-\u4DBF\u4E00-\u9FFF"
    r"\uF900-\uFAFF\U00020000-\U0003347F]"
)
SKIP_DIRS = {
    ".git", ".idea", ".codex", ".terraform", ".terragrunt-cache",
    "__pycache__", "local", "node_modules", "vendor",
}
TEXT_SUFFIXES = {
    ".md", ".go", ".py", ".sh", ".tf", ".hcl", ".tftpl", ".service",
    ".sql", ".yaml", ".yml", ".toml", ".txt", ".example", ".tfvars", ".nft", ".cjs",
}
TEXT_NAMES = {"Makefile", "LICENSE", ".gitignore", "go.mod", "go.sum", "Dockerfile"}
TEXT_NAMES |= {"control", "changelog", "rules", "copyright", "format"}
TEXT_SUFFIXES |= {".install", ".docs", ".postinst", ".prerm", ".manpages", ".lintian-overrides", ".8"}
MAX_BYTES = 2 * 1024 * 1024


def violations(text):
    return sorted({text.count("\n", 0, match.start()) + 1
                   for match in FORBIDDEN.finditer(text)})


def check(root):
    checked, issues = 0, []
    for directory, dirs, files in os.walk(root, followlinks=False):
        parent = Path(directory)
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
        for name in list(dirs) + sorted(files):
            path = parent / name
            relative = str(path.relative_to(root))
            if FORBIDDEN.search(relative):
                issues.append((relative, 0, "forbidden-script-in-path"))
            if path.is_symlink():
                issues.append((relative, 0, "symlink-requires-review"))
                if name in dirs:
                    dirs.remove(name)
                continue
            if name in dirs:
                continue
            if name == ".terraform.lock.hcl":
                continue
            if path.suffix not in TEXT_SUFFIXES and name not in TEXT_NAMES and not name.endswith(".example.json"):
                continue
            try:
                fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                with os.fdopen(fd, "rb") as handle:
                    info = os.fstat(handle.fileno())
                    if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_BYTES:
                        raise ValueError
                    data = handle.read(MAX_BYTES + 1)
                if len(data) > MAX_BYTES or b"\0" in data:
                    raise ValueError
                text = data.decode("utf-8")
            except (OSError, UnicodeError, ValueError):
                issues.append((relative, 0, "unreadable-or-nontext-source"))
                continue
            checked += 1
            issues.extend((relative, line, "literal-cyrillic-or-han") for line in violations(text))
    return checked, issues


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", nargs="?", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    if not args.root.is_dir() or args.root.is_symlink():
        parser.error("root must be a real directory")
    checked, issues = check(args.root.resolve())
    print(f"Language check: {checked} text files; {len(issues)} findings")
    for path, line, reason in issues:
        print(f"{json.dumps(path)}:{line}: {reason}")
    return bool(issues)


if __name__ == "__main__":
    sys.exit(main())
