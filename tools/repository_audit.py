#!/usr/bin/env python3
# Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
# Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
# SPDX-License-Identifier: AGPL-3.0-only
"""Read-only source audit. No Git, subprocesses, network or secret-store access."""
import argparse
from fnmatch import fnmatchcase
import json
import os
from pathlib import Path
import re
import stat
import sys

ROOT = Path(__file__).resolve().parents[1]
SOURCE_DIRS = {"cmd", "internal", "examples", "testdata", "docs", "tools", "ci", ".github", "debian"}
LOCAL_DIRS = {".git", ".idea", ".codex", "__pycache__", ".terraform", ".terragrunt-cache"}
LOCAL_FILES = {"AGENTS.md", "AGENT_NOTES.md", ".DS_Store"}
LOCAL_PATTERNS = (
    "DRAFT_*.md", "*.pyc", "*.pem", "*.key", "*.p12", "*.pfx", "*.ovpn",
    ".env", ".env.*", "*.tfstate", "*.tfstate.*", "*.tfvars", "*.tfvars.json",
    "*.zip", "*.tar", "*.tar.gz", "*.tgz", "*.log", "*.test", "*.out",
    "*.pprof", "*.prof", "*.swp", "*.swo", "*~",
)
LOCAL_RUNTIME_FILES = {
    "idp-metadata.xml", "okta-idp-metadata.xml", "supivpn", "supivpn-controller",
    "supivpn-profile", "supivpn-migrate", "bootstrap",
}
MAX_BYTES = 2 * 1024 * 1024
PATTERNS = {
    "private-key-material": re.compile(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----"),
    "cloud-access-key": re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    "access-token": re.compile(r"\b(?:glpat-[A-Za-z0-9_-]{15,}|gh[pousr]_[A-Za-z0-9]{20,}|xox[baprs]-[A-Za-z0-9-]{15,})\b"),
    "jwt-literal": re.compile(r"\beyJ[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b"),
    "credential-in-url": re.compile(r"[a-z][a-z0-9+.-]*://[^/\s\"'<>:]+:[^@\s\"'<>]+@", re.I),
    "personal-checkout-path": re.compile(r"/(?:Users|home)/[A-Za-z0-9_.-]+/"),
    "deployment-checkout-reference": re.compile(r"(?:\.\./infra\b|/infra/[a-z0-9_-]+\b)", re.I),
    "idp-tenant-identifier": re.compile(r"\b(?:00[ug]|exk)[A-Za-z0-9]{12,}\b"),
    "credential-literal": re.compile(
        r"(?:password|secret|api[_-]?key|access[_-]?token)\s*[=:]\s*[\"'][A-Za-z0-9_+/.=-]{24,}[\"']", re.I),
}
EXAMPLE_ACCOUNTS = {"000000000000", "111111111111", "222222222222", "111122223333", "123456789012"}
# Exact synthetic negative-test inputs, reviewed here; no blanket test-file bypass.
REVIEWED_TEST_LITERALS = {
    "internal/agent/groups_test.go": {("idp-tenant-identifier", "00g" + "1" * 17)},
    "internal/agentclient/client_test.go": {("credential-in-url", "https://" + "u:p@")},
}


def excluded(path):
    parts = path.parts
    return (
        any(part in LOCAL_DIRS for part in parts)
        or parts[:2] == ("runtime", "local")
        or parts[0] in {"security", "local", "dist", "build"}
        or path.name in LOCAL_FILES
        or any(fnmatchcase(path.name, pattern) for pattern in LOCAL_PATTERNS)
        or (len(parts) == 2 and parts[0] == "runtime" and path.name in LOCAL_RUNTIME_FILES)
    )


def permitted(path):
    if len(path.parts) == 1:
        return path.name in {".gitignore", "LICENSE", "REUSE.toml", "Makefile", "go.mod", "go.sum", "THIRD_PARTY_LICENSES.txt"} or path.suffix == ".md"
    if path.parts[0] not in SOURCE_DIRS:
        return False
    if path.parts[0] == ".github":
        return path.suffix in {".yml", ".yaml", ".md"} or path.name == "CODEOWNERS"
    if path.parts[0] == "tools":
        return path.suffix in {".py", ".md"}
    if path.parts[0] == "debian":
        return (path.as_posix() in {
            "debian/control", "debian/changelog", "debian/rules", "debian/copyright",
            "debian/source/format", "debian/supivpn-node.install",
            "debian/supivpn-controller.install", "debian/supivpn-controller.postinst",
            "debian/supivpn-node.postinst", "debian/supivpn-node.prerm", "debian/supivpn-controller.prerm",
            "debian/supivpn.docs", "debian/supivpn-node.docs", "debian/supivpn-controller.docs",
            "debian/supivpn.install", "debian/supivpn.manpages",
            "debian/supivpn-cli.install", "debian/supivpn-cli.docs", "debian/supivpn-cli.manpages", "debian/supivpn-cli.lintian-overrides",
            "debian/supivpn-node.manpages", "debian/supivpn-controller.manpages",
            "debian/supivpn-node.lintian-overrides", "debian/supivpn-controller.lintian-overrides",
        } or (path.parent == Path("debian/man") and path.name in {
            "supivpn.8", "supivpn-profile.8", "supivpn-controller.8", "supivpn-migrate.8", "supivpn-setup.8", "supivpn-cli.8",
        }) or (path.parent == Path("debian/units") and path.name in {
            "supivpn-node.service", "supivpn-openvpn.service", "supivpn-controller.service",
            "supivpn-node@.service", "supivpn-openvpn@.service",
        }) or (path.parent == Path("debian/examples") and path.name in {
            "agent.example.json", "controller.example.json", "server.conf.example", "setup.example.json",
        }))
    if path.parts[0] == "ci":
        if path.as_posix() in {"ci/okta/run.cjs", "ci/okta/profile.cjs", "ci/okta/run.test.cjs"}:
            return True
        return (path.suffix in {".py", ".sh", ".yaml", ".md", ".example", ".nft"}
                or path.name in {"Dockerfile", ".dockerignore"} or path == Path("ci/signers.json"))
    if path.parts[0] == "docs":
        return path.suffix == ".md"
    return (
        path.suffix in {".go", ".md", ".sql"}
        or path.name in {".gitignore", "go.mod", "go.sum", "Dockerfile", "THIRD_PARTY_LICENSES.txt"}
        or path.name.endswith(".example.json")
        or path.name in {"client.ovpn.example", "server.conf.example"}
    )


def findings(text, forbidden=(), relative=""):
    result = []
    for category, pattern in PATTERNS.items():
        for match in pattern.finditer(text):
            if (category, match[0]) in REVIEWED_TEST_LITERALS.get(relative, set()):
                continue
            result.append((text.count("\n", 0, match.start()) + 1, category))
    for match in re.finditer(r"\barn:aws(?:-[a-z]+)?:[a-z0-9-]*:[a-z0-9-]*:(\d{12}):", text):
        if match[1] not in EXAMPLE_ACCOUNTS:
            result.append((text.count("\n", 0, match.start()) + 1, "non-example-aws-account"))
    for value in forbidden:
        for match in re.finditer(re.escape(value), text, flags=re.I):
            result.append((text.count("\n", 0, match.start()) + 1, "forbidden-deployment-text"))
    return sorted(set(result))


def audit(root, forbidden=()):
    candidates, ignored, issues = [], [], []

    def walk(directory):
        for entry in sorted(directory.iterdir()):
            relative = entry.relative_to(root)
            # Never follow links, even inside otherwise excluded paths.
            if entry.is_symlink():
                issues.append((str(relative), 0, "symbolic-link-requires-review"))
                continue
            if excluded(relative):
                ignored.append(str(relative))
                continue
            if entry.is_dir():
                if len(relative.parts) == 1 and relative.name not in SOURCE_DIRS:
                    ignored.append(str(relative))
                    continue
                walk(entry)
                continue
            if len(relative.parts) == 1 and not permitted(relative):
                ignored.append(str(relative))
                continue
            if not permitted(relative):
                issues.append((str(relative), 0, "unexpected-source-file"))
                continue
            try:
                descriptor = os.open(entry, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                with os.fdopen(descriptor, "rb") as handle:
                    info = os.fstat(handle.fileno())
                    if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_BYTES:
                        issues.append((str(relative), 0, "nonregular-or-oversized-source"))
                        continue
                    raw = handle.read(MAX_BYTES + 1)
                text = raw.decode("utf-8")
            except (OSError, UnicodeError):
                issues.append((str(relative), 0, "unreadable-or-binary-source"))
                continue
            if b"\0" in raw or len(raw) > MAX_BYTES:
                issues.append((str(relative), 0, "binary-or-oversized-source"))
                continue
            candidates.append(str(relative))
            issues.extend((str(relative), line, reason) for line, reason in findings(text, forbidden, str(relative)))
    walk(root)
    return candidates, ignored, issues


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--forbid", action="append", default=[], help="extra deployment text to reject; never printed")
    parser.add_argument("--inventory", action="store_true", help="list candidate paths, never file contents")
    args = parser.parse_args()
    candidates, ignored, issues = audit(ROOT, args.forbid)
    print(f"Source candidates: {len(candidates)}; excluded paths/subtrees: {len(ignored)}; findings: {len(issues)}")
    if args.inventory:
        for path in candidates:
            print(json.dumps(path))
        print("Excluded (contents not scanned):")
        for path in ignored:
            print(json.dumps(path))
    for path, line, category in issues:
        print(f"{json.dumps(path)}:{line}: {category}")
    if not issues:
        print("No configured secret/deployment patterns found in candidate source files.")
        print("This is a heuristic working-tree check, not a Git index audit or proof that no secrets exist.")
    return bool(issues)


if __name__ == "__main__":
    sys.exit(main())
