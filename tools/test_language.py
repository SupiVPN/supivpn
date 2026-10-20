# Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
# Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
# SPDX-License-Identifier: AGPL-3.0-only
from pathlib import Path
import tempfile
import unittest

import check_language as language


class LanguageTests(unittest.TestCase):
    def test_detects_scripts_including_supplementary_planes(self):
        for value in ("\u042f", "\u1c80", "\u4e2d", "\U00020000", "\U0001e030"):
            self.assertEqual(language.violations("English\n" + value), [2])
        self.assertEqual(language.violations(r"English \u042f \u4e2d"), [])
        self.assertEqual(language.violations("English: caf\u00e9 -> OK"), [])

    def test_checks_docs_comments_and_paths_without_reading_local_data(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "local").mkdir()
            (root / "local/secret.key").write_bytes(b"\0")
            (root / "README.md").write_text("English\n\u042f\n", encoding="utf-8")
            (root / "AGENTS.md").write_text("English", encoding="utf-8")
            (root / ("\u4e2d" + ".py")).write_text("# English", encoding="utf-8")
            (root / "link.md").symlink_to(root / "local/secret.key")
            checked, issues = language.check(root)
            self.assertEqual(checked, 3)
            self.assertEqual({i[2] for i in issues}, {
                "literal-cyrillic-or-han", "forbidden-script-in-path", "symlink-requires-review"})
            self.assertFalse(any("secret.key" in i[0] for i in issues))
