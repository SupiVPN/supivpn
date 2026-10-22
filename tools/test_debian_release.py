# Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
# SPDX-License-Identifier: AGPL-3.0-only
"""Refuse mismatched versions, package identities and modified Debian source."""
import io
from pathlib import Path
import subprocess
import tarfile
import unittest
from unittest.mock import patch

import artifacts as a
import debian_release as deb
from test_github_release import debian_files, SOURCE, EPOCH, V


class DebianReleaseTests(unittest.TestCase):
    def test_version_conversion_preserves_debian_prerelease_order(self):
        for tag, value in (("v1.2.3", "1.2.3"), ("v1.2.3-rc.2", "1.2.3~rc.2"),
                           ("v0.6.0-beta.1", "0.6.0~beta.1")):
            self.assertEqual(deb.version(tag), value)
        for tag in ("v01.2.3", "1.2.3", "v1.2.3-rc.01", "v1.2.3;whoami", "../../other"):
            with self.assertRaises(a.ValidationError):
                deb.filenames(tag, "arm64")

    def test_descriptor_and_source_are_bound_to_exact_tag(self):
        files = debian_files("arm64")
        archive = files[f"supivpn_{deb.version(V)}.tar.xz"]
        descriptor = files[f"supivpn_{deb.version(V)}.dsc"]
        deb.verify_source(archive, descriptor, V, SOURCE, EPOCH)
        deb.verify_source(archive, descriptor, V, dict(SOURCE, **{".gitignore": (b"local/\n", 0o644)}), EPOCH)
        with self.assertRaises(a.ValidationError):
            deb.verify_source(archive, descriptor, V, dict(SOURCE, **{"debian/control": (b"missing", 0o644)}), EPOCH)
        with self.assertRaises(a.ValidationError):
            deb.verify_source(archive, descriptor.replace(a.sha(archive).encode(), b"0" * 64), V, SOURCE, EPOCH)
        with self.assertRaises(a.ValidationError):
            deb.verify_source(archive, descriptor, V, SOURCE, EPOCH + 1)
        for name, kind in (("source/../outside", tarfile.REGTYPE),
                           ("source/debian/rules", tarfile.SYMTYPE),
                           ("source/LICENSE", tarfile.REGTYPE)):
            output = io.BytesIO()
            with tarfile.open(fileobj=output, mode="w:xz") as altered:
                with tarfile.open(fileobj=io.BytesIO(archive), mode="r:xz") as original:
                    for member in original:
                        altered.addfile(member, original.extractfile(member))
                item = tarfile.TarInfo(name)
                item.type, item.size = kind, 1
                altered.addfile(item, io.BytesIO(b"x"))
            with self.assertRaises(a.ValidationError):
                deb.verify_source(output.getvalue(), descriptor, V, SOURCE, EPOCH)

    def test_package_identity_and_exact_metapackage_dependencies(self):
        value = deb.version(V)
        path = Path(f"supivpn_{value}_all.deb")
        fields = {"Package": "supivpn", "Version": value, "Architecture": "all",
                  "Depends": f"supivpn-node (= {value}), supivpn-controller (= {value}), python3"}
        def reply(changes):
            text = "".join(f"{key}: {value}\n" for key, value in dict(fields, **changes).items())
            return subprocess.CompletedProcess([], 0, text, "")
        with patch.object(deb.subprocess, "run", return_value=reply({})):
            deb.verify_package(path, V, "arm64")
        for changes in ({"Package": "openvpn"}, {"Version": "9.9.9"}, {"Architecture": "amd64"},
                        {"Depends": "supivpn-node, supivpn-controller"}):
            with patch.object(deb.subprocess, "run", return_value=reply(changes)), self.assertRaises(a.ValidationError):
                deb.verify_package(path, V, "arm64")
