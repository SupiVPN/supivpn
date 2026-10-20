# Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
# Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
# SPDX-License-Identifier: AGPL-3.0-only
"""Release-note validation without Git or network access."""
from pathlib import Path
import contextlib
import io
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import release_notes as notes

VERSION = "v1.2.3"
TEXT = ("# SupiVPN " + VERSION + "\n\n## Changes\n\n"
        "- Improve release delivery for operators.\n\n## Compatibility\n\n"
        "- No runtime or database compatibility changes.\n")

COMMIT = "a" * 40


def signed_tag(version=VERSION, commit=COMMIT, text=TEXT):
    # Structure fixture only; cryptographic verification has separate tests.
    return ("object " + commit + "\ntype commit\ntag " + version
            + "\ntagger Test <test@example.invalid> 1 +0000\n\n" + text
            + "-----BEGIN PGP SIGNATURE-----\nfixture\n-----END PGP SIGNATURE-----\n")


class NotesTests(unittest.TestCase):
    def test_versions_title_content_and_placeholders(self):
        self.assertEqual(notes.validate(VERSION, TEXT), TEXT)
        for version in ("../v1.2.3", "latest", "v01.2.3", "v1.2.3-rc.01", VERSION + "\n"):
            with self.subTest(version=version), self.assertRaises(ValueError):
                notes.validate(version, TEXT)
        for text in ("", TEXT.replace(VERSION, "v2.0.0"), TEXT + "\nTODO details\n",
                     TEXT.replace("## Changes", "## Other"), TEXT + "\n## Compatibility\n\nAnother section.\n",
                     TEXT.replace("- Improve release delivery for operators.", ""), TEXT + "\0",
                     TEXT + "x" * notes.MAX_NOTES):
            with self.subTest(text=text[:40]), self.assertRaises(ValueError):
                notes.validate(VERSION, text)

    def test_missing_symlink_and_oversized_notes_are_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            path = root / notes.notes_path(VERSION)
            path.parent.mkdir(parents=True)
            with self.assertRaises(OSError):
                notes.load(root, VERSION)
            path.write_text(TEXT)
            self.assertEqual(notes.load(root, VERSION), TEXT)
            other = path.with_name("other.md")
            other.write_text(TEXT)
            path.unlink()
            path.symlink_to(other)
            with self.assertRaises(ValueError):
                notes.load(root, VERSION)
            path.unlink()
            path.write_bytes(b"x" * (notes.MAX_NOTES + 1))
            with self.assertRaises(ValueError):
                notes.load(root, VERSION)

    def test_checked_in_notes_are_valid(self):
        paths = list((notes.ROOT / "docs/releases").glob("v*.md"))
        for path in paths:
            notes.load(notes.ROOT, path.stem)

    def test_audit_allows_tag_only_notes_but_rejects_invalid_checked_in_notes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            folder = root / "docs/releases"
            folder.mkdir(parents=True)
            (folder / "README.md").write_text("# Release notes\n")
            with patch.object(notes, "ROOT", root), patch("sys.argv", ["notes", "--audit"]), \
                    contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(notes.main(), 0)
                (folder / (VERSION + ".md")).write_text(TEXT)
                self.assertEqual(notes.main(), 0)
                (folder / (VERSION + ".md")).write_text("# Invalid notes\n")
                self.assertEqual(notes.main(), 1)

class GeneratedNotesTests(unittest.TestCase):
    def test_history_generation_escapes_subjects_and_links_exact_commits(self):
        subject = "Fix [link](https://example.invalid) <script> @team `code`"
        history = COMMIT + "\t" + subject + "\n"
        text = notes.generate(VERSION, COMMIT, history, "v1.2.2")
        self.assertTrue(text.startswith("# SupiVPN " + VERSION + "\n"))
        self.assertIn("Changes since [v1.2.2]", text)
        self.assertIn("/commit/" + COMMIT, text)
        self.assertNotIn("<script>", text)
        self.assertNotIn("[link](", text)
        self.assertNotIn("@team", text)
        self.assertIn("&#64;team", text)
        self.assertIn("do not assert runtime or migration compatibility", text)
        self.assertEqual(text, notes.generate(VERSION, COMMIT, history, "v1.2.2"))

    def test_initial_release_and_promotion_without_source_changes(self):
        self.assertIn("Changes through commit", notes.generate(VERSION, COMMIT, COMMIT + "\tInitial release\n"))
        self.assertIn("No source changes since v1.2.3-rc.1",
                      notes.generate(VERSION, COMMIT, "", "v1.2.3-rc.1"))
        with self.assertRaises(ValueError):
            notes.generate(VERSION, COMMIT, "")

    def test_legitimate_todo_word_in_commit_subject_is_not_a_notes_placeholder(self):
        text = notes.generate(VERSION, COMMIT, COMMIT + "\tResolve FIXME in release validation\n")
        with patch.object(notes, "git_tag", return_value=signed_tag(text=text)):
            self.assertEqual(notes.load_tag(Path("/checkout"), VERSION, COMMIT), text)

    def test_semver_numeric_and_prerelease_order(self):
        versions = ["v1.2.3", "v1.2.3-rc.10", "v1.2.3-rc.9", "v1.2.3-beta.2", "v1.2.3-alpha.1"]
        self.assertEqual(sorted(versions, key=notes.version_order, reverse=True), versions)
        self.assertGreater(notes.version_order("v1.10.0"), notes.version_order("v1.9.9"))
        with self.assertRaises(ValueError):
            notes.version_order("v1.02.3")

    def test_malformed_duplicate_and_oversized_history_refused(self):
        for history in ("bad", COMMIT + "\t\n", "0" * 40 + "\tZero\n",
                        COMMIT + "\tControl\x1b\n", COMMIT + "\t" + "x" * 1025,
                        (COMMIT + "\tDuplicate\n") * 2,
                        "\n".join(format(n, "040x") + "\tChange" for n in range(1, 258)),
                        "x" * (1024 * 1024 + 1)):
            with self.subTest(history=history[:60]), self.assertRaises(ValueError):
                notes.generate(VERSION, COMMIT, history)


class TagNotesTests(unittest.TestCase):
    def test_reads_exact_frozen_notes_without_history_or_notes_file(self):
        with patch.object(notes, "git_tag", return_value=signed_tag()) as read:
            self.assertEqual(notes.load_tag(Path("/checkout"), VERSION, COMMIT), TEXT)
        read.assert_called_once_with(Path("/checkout"), VERSION)

    def test_wrong_identity_unsigned_trailing_or_duplicate_signature_refused(self):
        raw = signed_tag()
        for data in (signed_tag(commit="b" * 40), signed_tag(version="v9.0.0"),
                     raw.replace("type commit", "type tag"),
                     raw.replace("-----BEGIN PGP SIGNATURE-----", "unsigned"),
                     raw + "extra text", raw + raw,
                     raw.replace("tagger Test", "object " + COMMIT + "\ntagger Test"),
                     raw.replace(TEXT, "SupiVPN " + VERSION + "\n"), "x" * (notes.MAX_TAG + 1)):
            with self.subTest(data=data[:60]), patch.object(notes, "git_tag", return_value=data):
                with self.assertRaises(ValueError):
                    notes.load_tag(Path("/checkout"), VERSION, COMMIT)

    def test_reader_is_local_read_only_bounded_and_hides_raw_diagnostics(self):
        with patch.object(notes.subprocess, "run") as run:
            run.return_value = subprocess.CompletedProcess([], 0, signed_tag(), "")
            self.assertEqual(notes.git_tag(notes.ROOT, VERSION), signed_tag())
            args, kwargs = run.call_args.args[0], run.call_args.kwargs
            self.assertEqual(args[-3:], ["cat-file", "tag", "refs/tags/" + VERSION])
            self.assertEqual(kwargs["env"]["GIT_NO_REPLACE_OBJECTS"], "1")
            self.assertEqual(kwargs["timeout"], 15)
            self.assertNotIn("shell", kwargs)
            run.return_value = subprocess.CompletedProcess([], 128, "", "private diagnostic")
            with self.assertRaisesRegex(ValueError, "^Cannot read local release tag$"):
                notes.git_tag(notes.ROOT, VERSION)
            run.side_effect = subprocess.TimeoutExpired("git", 15, stderr="private diagnostic")
            with self.assertRaisesRegex(ValueError, "^Cannot read local release tag$"):
                notes.git_tag(notes.ROOT, VERSION)

    def test_cli_uses_tag_and_verified_sha_without_regenerating_notes(self):
        with patch.object(sys, "argv", ["release_notes.py", "--tag", VERSION, "--commit", COMMIT]), \
                patch.object(notes, "load_tag", return_value=TEXT) as load, \
                patch.object(notes, "generate") as generate, contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(notes.main(), 0)
        load.assert_called_once_with(notes.ROOT, VERSION, COMMIT)
        generate.assert_not_called()


if __name__ == "__main__":
    unittest.main()
