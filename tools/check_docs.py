#!/usr/bin/env python3
# Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
# Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
# SPDX-License-Identifier: AGPL-3.0-only
"""Check changed Markdown and local links without network requests or code builds."""
import argparse
from pathlib import Path
import re
import subprocess
from urllib.parse import unquote, urlsplit


def git(root, *args):
    return subprocess.run(["git", "-C", str(root), *args], check=True,
                          capture_output=True, timeout=30).stdout.decode("utf-8")


def prose(text):
    # Ignore fenced examples; links inside inline code are also not navigable.
    lines, fence = [], None
    for line in text.splitlines():
        marker = re.match(r"^\s{0,3}(`{3,}|~{3,})", line)
        if marker:
            token = marker[1]
            if fence is None:
                fence = token
            elif token[0] == fence[0] and len(token) >= len(fence):
                fence = None
            continue
        if fence is None:
            lines.append(line)
    return "\n".join(lines)


def anchors(text):
    seen, result = {}, set()
    for heading in re.findall(r"^#{1,6}\s+(.+?)\s*#*$", prose(text), re.M):
        heading = re.sub(r"<[^>]+>", "", heading)
        heading = re.sub(r"\[([^]]+)\]\([^)]*\)", r"\1", heading)
        slug = re.sub(r"[^\w\- ]", "", heading.lower()).replace(" ", "-")
        count = seen.get(slug, 0)
        seen[slug] = count + 1
        result.add(slug + (f"-{count}" if count else ""))
    result.update(re.findall(r'''\b(?:id|name)=["']([^"']+)["']''', text))
    return result


def check(root, base, head):
    root = root.resolve()
    if not all(re.fullmatch(r"[0-9a-f]{40}", sha) for sha in (base, head)):
        raise ValueError("Full commit IDs are required")
    if git(root, "rev-parse", "HEAD").strip() != head:
        # PR checkouts use a test merge. Its tree must contain the PR head.
        git(root, "merge-base", "--is-ancestor", head, "HEAD")
    git(root, "diff", "--check", base, head, "--")
    changed = git(root, "diff", "--no-ext-diff", "--no-renames", "--name-only", "-z",
                  base, head, "--").split("\0")
    tracked = set(git(root, "ls-files", "-z").split("\0"))
    errors, checked = [], 0
    for name in changed:
        if not name or not name.endswith(".md") or name not in tracked:
            continue
        path = root / name
        if path.is_symlink() or not path.is_file():
            raise ValueError("Markdown must be a regular file")
        text = path.read_text(encoding="utf-8")
        if re.search(r"^(?:<{7}|={7}|>{7})(?: |$)", text, re.M):
            errors.append(f"{name}: unresolved conflict marker")
        source = re.sub(r"(`+).*?\1", "", prose(text))
        links = re.findall(r"!?\[[^\]\n]*\]\(<?([^\s)>]+)>?(?:\s+[^)]*)?\)", source)
        links += re.findall(r"^\s{0,3}\[[^]]+\]:\s*<?([^\s>]+)", source, re.M)
        for link in links:
            url = urlsplit(link)
            if url.scheme or url.netloc:
                continue
            target = path.parent / unquote(url.path) if url.path else path
            resolved = target.resolve()
            if not resolved.is_relative_to(root):
                errors.append(f"{name}: local link leaves repository: {link}")
                continue
            relative = resolved.relative_to(root).as_posix()
            # A tracked directory link is valid; ignored local artifacts are not.
            if (relative != "." and relative not in tracked
                    and not any(p.startswith(relative + "/") for p in tracked)):
                errors.append(f"{name}: missing tracked target: {link}")
                continue
            if target.is_symlink():
                errors.append(f"{name}: symbolic link target: {link}")
                continue
            if url.fragment and target.suffix == ".md":
                if unquote(url.fragment) not in anchors(target.read_text(encoding="utf-8")):
                    errors.append(f"{name}: missing heading: {link}")
            checked += 1
    return checked, errors


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", required=True)
    parser.add_argument("--head", required=True)
    args = parser.parse_args()
    try:
        count, errors = check(Path(__file__).resolve().parents[1], args.base, args.head)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(f"Documentation check failed ({type(error).__name__})")
        return 1
    print(f"Local documentation links checked: {count}; findings: {len(errors)}")
    for error in errors:
        print(error)
    return bool(errors)


if __name__ == "__main__":
    raise SystemExit(main())
