# Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
# SPDX-License-Identifier: AGPL-3.0-only
"""Never boot a substituted or corrupt cached/downloaded VM image."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace

import debian_vm


class ImageIntegrityTests(unittest.TestCase):
    def test_corrupt_cached_image_fails_before_running_tools(self):
        with tempfile.TemporaryDirectory() as directory:
            cache = Path(directory)
            target = cache / f"debian-13-generic-arm64-{debian_vm.IMAGE_VERSION}.qcow2"
            target.write_bytes(b"not a Debian image")
            with patch.object(debian_vm, "run") as run:
                with self.assertRaisesRegex(ValueError, "checksum mismatch"):
                    debian_vm.image(cache, "arm64")
                run.assert_not_called()

    def test_symlink_is_rejected_without_reading_its_target(self):
        with tempfile.TemporaryDirectory() as directory:
            cache = Path(directory)
            other = cache / "unrelated-fixture"
            other.write_bytes(b"not image input")
            target = cache / f"debian-13-generic-arm64-{debian_vm.IMAGE_VERSION}.qcow2"
            target.symlink_to(other)
            with patch.object(debian_vm, "digest") as digest, patch.object(debian_vm, "run") as run:
                with self.assertRaises(ValueError):
                    debian_vm.image(cache, "arm64")
                digest.assert_not_called()
                run.assert_not_called()

    def test_bad_download_never_becomes_a_cached_image(self):
        with tempfile.TemporaryDirectory() as directory:
            cache = Path(directory)
            def download(args, **kwargs):
                self.assertEqual(args[args.index("--proto") + 1], "=https")
                self.assertEqual(args[args.index("--proto-redir") + 1], "=https")
                Path(args[-1]).write_bytes(b"corrupted download")
            with patch.object(debian_vm, "run", side_effect=download):
                with self.assertRaisesRegex(ValueError, "checksum mismatch"):
                    debian_vm.image(cache, "amd64")
            self.assertFalse(list(cache.glob("*.qcow2")))


class RemoteDatabaseTests(unittest.TestCase):
    def test_unknown_mode_never_downloads_or_runs_a_vm(self):
        with patch.object(debian_vm, "run") as run, patch.object(debian_vm, "image") as image:
            with self.assertRaisesRegex(ValueError, "database mode"):
                debian_vm.run_vm(Path("unused"), Path("unused"), "arm64", "docker", "go", database="unknown")
            run.assert_not_called()
            image.assert_not_called()

    def test_database_timeout_stops_only_its_container_and_keeps_passwords_out_of_commands(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, work = root / "source", root / "work"
            (source / "ci/debian/vm").mkdir(parents=True)
            (source / "ci/debian/vm/database.py").write_text("# synthetic fixture\n")
            work.mkdir()
            with patch.object(debian_vm, "run", return_value=SimpleNamespace(stdout="owned-db-id\n")) as run, \
                 patch.object(debian_vm.time, "monotonic", side_effect=[0, 91]):
                with self.assertRaises(TimeoutError):
                    debian_vm.external_database(source, work, "docker", "owned-vm-id", "arm64")
            calls = [call.args[0] for call in run.call_args_list]
            self.assertEqual(calls[-1], ["docker", "stop", "--time", "10", "owned-db-id"])
            database_run = calls[1]
            self.assertEqual(database_run[database_run.index("--network") + 1], "container:owned-vm-id")
            self.assertNotIn("--publish", database_run)
            for filename in ("runtime.password", "migration.password"):
                path = work / "database" / filename
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
                self.assertNotIn(path.read_text(), repr(calls))


if __name__ == "__main__":
    unittest.main()
