# Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
# SPDX-License-Identifier: AGPL-3.0-only
"""Never boot a substituted or corrupt cached/downloaded VM image."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

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


if __name__ == "__main__":
    unittest.main()
