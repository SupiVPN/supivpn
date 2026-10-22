# Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
# SPDX-License-Identifier: AGPL-3.0-only
"""Keep isolated package builds from copying private or unaudited workspace data."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import debian_packages
import debian_release
import repository_audit


class DebianSourceTests(unittest.TestCase):
    def test_release_changelog_and_source_times_are_deterministic_without_editing_checkout(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "repo"
            (root / "debian").mkdir(parents=True)
            original = b"supivpn (0.5.0+packaging1) UNRELEASED; urgency=medium\n"
            (root / "debian/changelog").write_bytes(original)
            for name in ("one", "two"):
                work = Path(directory) / name
                work.mkdir()
                with patch.object(debian_packages, "run"):
                    source = debian_packages.prepare(root, work, "go", version="v0.6.0-rc.1", epoch=1792684800)
                self.assertEqual((source / "debian/changelog").read_bytes(),
                                 debian_release.changelog(original, "v0.6.0-rc.1", 1792684800))
                self.assertEqual((source / "debian/changelog").stat().st_mtime, 1792684800)
            self.assertEqual((root / "debian/changelog").read_bytes(), original)

    def test_copies_only_audited_source_and_never_local_material(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "repo"
            root.mkdir()
            (root / "local").mkdir()
            (root / "local/private.json").write_text("must not be copied")
            (root / "AGENTS.md").write_text("local policy")
            (root / "debian").mkdir()
            (root / "debian/control").write_text("Source: supivpn\n")
            (root / "debian/rules").write_text("#!/usr/bin/make -f\n")
            work = Path(directory) / "build"
            work.mkdir()
            with patch.object(debian_packages, "run") as run:
                source = debian_packages.prepare(root, work, "go")
            self.assertFalse((source / "local").exists())
            self.assertFalse((source / "AGENTS.md").exists())
            self.assertEqual((source / "debian/control").read_text(), "Source: supivpn\n")
            self.assertEqual((source / "debian/rules").stat().st_mode & 0o777, 0o755)
            self.assertEqual(run.call_args_list[0].args[0], ["go", "mod", "verify"])

    def test_unsafe_input_stops_before_any_subprocess(self):
        for kind in ("unexpected", "symlink", "secret"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / "debian").mkdir()
                if kind == "unexpected":
                    (root / "debian/credentials.json").write_text("{}")
                elif kind == "symlink":
                    (root / "debian/control").symlink_to(root / "outside")
                else:
                    (root / "debian/control").write_text("glpat-" + "a" * 24)
                with patch.object(debian_packages, "run") as run:
                    with self.assertRaises(ValueError):
                        debian_packages.prepare(root, root / "build", "go")
                    run.assert_not_called()

    def test_packaging_allowlist_does_not_admit_outputs(self):
        for path in ("debian/credentials.json", "debian/bin/supivpn", "debian/files",
                     "debian/supivpn/DEBIAN/control", "debian/units/arbitrary.service"):
            self.assertFalse(repository_audit.permitted(Path(path)), path)


if __name__ == "__main__":
    unittest.main()
