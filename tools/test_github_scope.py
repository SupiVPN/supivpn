# Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
# Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
# SPDX-License-Identifier: AGPL-3.0-only
"""Exercise CI selection against real Git histories, including renames and pushes."""
import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import check_docs

SPEC = importlib.util.spec_from_file_location("github_scope", Path(__file__).resolve().parents[1] / "ci/github_scope.py")
scope = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(scope)


class ScopeTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.env = dict(os.environ, GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1")
        self.git("init", "-q")
        self.base = self.commit({"README.md": "# Hello\n", "main.go": "package main\n"})
        real_git = scope.git
        def in_repository(*args):
            return real_git("-C", str(self.root), *args)
        self.mock = patch.object(scope, "git", side_effect=in_repository)
        self.mock.start()
        self.addCleanup(self.mock.stop)

    def git(self, *args):
        return subprocess.run(["git", "-C", str(self.root), *args], env=self.env,
                              check=True, capture_output=True, timeout=10).stdout.decode().strip()

    def commit(self, files):
        for name, text in files.items():
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            if text is None:
                path.unlink()
            else:
                path.write_text(text)
        self.git("add", "--all")
        self.git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                 "-c", "commit.gpgsign=false", "commit", "-qm", "Synthetic fixture")
        return self.git("rev-parse", "HEAD")

    def event(self, base, head, event="push", **overrides):
        values = {"GITHUB_EVENT_NAME": event, "GITHUB_REF": "refs/heads/main", "PUSH_FORCED": "false",
                  "BEFORE_SHA": base, "AFTER_SHA": head, "GITHUB_SHA": head,
                  "BASE_SHA": base, "HEAD_SHA": head}
        return dict(values, **overrides)

    def test_documentation_is_light_for_pr_and_main_push(self):
        head = self.commit({"README.md": "# Updated\n", "docs/guide.md": "# Guide\n"})
        for event in ("push", "pull_request"):
            self.assertEqual(scope.scope(self.event(self.base, head, event)), (False, self.base, head))

    def test_push_checks_all_commits_not_only_the_last_commit(self):
        self.commit({"main.go": "package changed\n"})
        head = self.commit({"README.md": "# Docs only in the last commit\n"})
        self.assertTrue(scope.scope(self.event(self.base, head))[0])

    def test_pr_uses_merge_base_but_push_uses_before_and_after(self):
        feature = self.commit({"README.md": "# Feature docs\n"})
        self.git("checkout", "-q", "-b", "advanced-main", self.base)
        main = self.commit({"main.go": "package advanced\n"})
        self.assertEqual(scope.scope(self.event(main, feature, "pull_request")), (False, self.base, feature))
        self.git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                 "-c", "commit.gpgsign=false", "merge", "-qm", "Merge fixture", feature)
        merged = self.git("rev-parse", "HEAD")
        self.assertEqual(scope.scope(self.event(main, merged)), (False, main, merged))

    def test_renaming_code_into_documentation_requires_full_checks(self):
        head = self.commit({"main.go": None, "docs/code.md": "package main\n"})
        self.assertTrue(scope.scope(self.event(self.base, head))[0])

    def test_release_scheduled_manual_unknown_and_empty_diff_stay_full(self):
        head = self.commit({"README.md": "# Updated\n"})
        for overrides in ({"GITHUB_EVENT_NAME": "schedule"}, {"GITHUB_EVENT_NAME": "workflow_dispatch"},
                          {"GITHUB_EVENT_NAME": "unknown"}, {"GITHUB_REF": "refs/tags/v0.8.2"},
                          {"GITHUB_REF": "refs/heads/other"}, {"PUSH_FORCED": "true"},
                          {"PUSH_FORCED": ""}, {"BEFORE_SHA": "0" * 40},
                          {"BEFORE_SHA": ""}, {"BEFORE_SHA": "--help"},
                          {"GITHUB_SHA": self.base}, {"BEFORE_SHA": "f" * 40}):
            with self.subTest(overrides=overrides):
                self.assertTrue(scope.scope(self.event(self.base, head, **overrides))[0])
        self.assertTrue(scope.scope(self.event(head, head))[0])
        self.assertTrue(scope.scope(self.event(head, self.base))[0])

    def test_unknown_paths_and_tooling_are_not_documentation(self):
        for path in (".github/workflows/checks.yml", "ci/github_scope.py", "go.mod", "go.sum",
                     "cmd/README.md", "THIRD_PARTY_NOTICES.md", "COPYRIGHT.md", "LICENSE"):
            self.assertTrue(scope.code_required("push", ["README.md", path]), path)

    def test_git_errors_and_invalid_utf8_fall_back_to_full_checks(self):
        env = self.event(self.base, "a" * 40)
        for error in (OSError(), subprocess.TimeoutExpired("git", 30), UnicodeError()):
            with patch.object(scope, "git", side_effect=error):
                self.assertTrue(scope.scope(env)[0])
        with patch.object(scope, "git", side_effect=[b"", b"\xff\0"]):
            self.assertTrue(scope.scope(env)[0])

    def test_documentation_links_fragments_references_and_code_examples(self):
        head = self.commit({
            "README.md": "# Hello\n[Guide](docs/guide.md#repeat-1)\n[Ref][guide]\n"
                         "[guide]: docs/guide.md#inline-code\n```md\n[Example](missing.md)\n```\n",
            "docs/guide.md": "# Repeat\n# Repeat\n## Inline `code`\n[Repository](../)\n",
        })
        count, errors = check_docs.check(self.root, self.base, head)
        self.assertEqual(count, 3)
        self.assertEqual(errors, [])

    def test_documentation_refuses_missing_untracked_and_external_local_targets(self):
        (self.root / "ignored.md").write_text("# Ignored\n")
        self.git("config", "core.excludesFile", str(self.root / "exclude"))
        (self.root / "exclude").write_text("ignored.md\nexclude\n")
        head = self.commit({"README.md": "# Hello\n[Missing](docs/missing.md)\n"
                           "[Ignored](ignored.md)\n[Outside](../outside.md)\n"
                           "[Anchor](#missing)\n[External](https://example.invalid/not-fetched)\n"})
        _, errors = check_docs.check(self.root, self.base, head)
        self.assertEqual(len(errors), 4)

    def test_documentation_refuses_conflicts_and_whitespace_errors(self):
        head = self.commit({"README.md": "# Hello\n<<<<<<< incoming\n"})
        # git diff --check itself also rejects conflict markers.
        with self.assertRaises(subprocess.CalledProcessError):
            check_docs.check(self.root, self.base, head)
        head = self.commit({"README.md": "# Hello  \n"})
        with self.assertRaises(subprocess.CalledProcessError):
            check_docs.check(self.root, self.base, head)


if __name__ == "__main__":
    unittest.main()
