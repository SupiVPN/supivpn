# Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
# Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
# SPDX-License-Identifier: AGPL-3.0-only
import hashlib
import gzip
import io
import json
import os
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import zipfile

import artifacts as a

V = "v1.2.3"
C = "a" * 40


def fixture(root, arch="arm64"):
    files = {name: b"synthetic public test content\n" for name in a.FIXED}
    for name in a.BINARIES:
        files["bin/" + name] = b"\x7fELF\x02\x01" + b"\0" * 12 + a.ELF_MACHINES[arch] + name.encode()
    migration = "migrations/001_initial.sql"
    files[migration] = b"SELECT 1;\n"
    schema = a.sha(("001_initial.sql:" + a.sha(files[migration]) + "\n").encode())
    for name, binary in a.LAMBDA_ZIPS.items():
        zipped = io.BytesIO()
        with zipfile.ZipFile(zipped, "w") as z:
            z.writestr("bootstrap", files["bin/" + binary])
            if binary == "bootstrap":
                z.writestr("client.ovpn.template", files["examples/client.ovpn.example"])
        files["lambda/" + name] = zipped.getvalue()
    release = {"format": 1, "schema": 1, "schema_digest": schema, "compatible_schemas": {"1": schema},
               "lambda_components": {component: {"artifact": artifact, "required_schema": 1}
                                     for component, artifact in a.LAMBDA_COMPONENTS.items()},
               "artifacts": {name: a.sha(files[a.artifact_path(name)]) for name in a.ARTIFACTS}}
    files["release.json"] = json.dumps(release).encode()
    for name, value in files.items():
        path = root / a.source_path(name, arch)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(value)
    return files


class ArtifactTests(unittest.TestCase):
    def test_checksum_bytes_are_sorted_and_stable(self):
        assets = {"z.tar.gz": "a" * 64, "a.tar.gz": "b" * 64}
        expected = ("b" * 64 + "  a.tar.gz\n" + "a" * 64 + "  z.tar.gz\n").encode("ascii")
        self.assertEqual(a.checksums(assets), expected)
        self.assertEqual(a.checksums(dict(reversed(list(assets.items())))), expected)

    def test_component_swap_is_rejected_even_with_updated_zip_checksum(self):
        files = fixture(self.root)
        files["lambda/supivpn-agent-lambda.zip"] = files["lambda/supivpn-recovery-lambda.zip"]
        release = json.loads(files["release.json"])
        release["artifacts"]["supivpn-agent-lambda.zip"] = a.sha(files["lambda/supivpn-agent-lambda.zip"])
        files["release.json"] = json.dumps(release).encode()
        with self.assertRaisesRegex(a.ValidationError, "Lambda binary mismatch"):
            a.validate_payload(files)

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve())
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        fixture(self.root)

    def bundle(self):
        path, digest = a.package(self.root, V, C, self.root / "output")
        return path.read_bytes(), digest

    def test_deterministic_bundle_roundtrip_and_offline_cache(self):
        data, digest = self.bundle()
        path, second = a.package(self.root, V, C, self.root / "other")
        self.assertEqual(path.read_bytes(), data)
        self.assertEqual(second, digest)
        cache = self.root / "cache"
        dest = a.unpack(data, digest, V, C, cache)
        self.assertEqual(a.unpack(data, digest, V, C, cache), dest)
        self.assertTrue((dest / "bin/supivpn").stat().st_mode & 0o111)
        (dest / "bin/supivpn").write_bytes(b"changed")
        with self.assertRaises(ValueError):
            a.unpack(data, digest, V, C, cache)

    def test_excludes_local_secrets_and_rejects_lambda_metadata(self):
        (self.root / "local/deployment.key").write_bytes(b"synthetic-not-a-key")
        (self.root / "local/ci").mkdir()
        (self.root / "local/ci/openvpn-arm64.test").write_bytes(b"CI-only executable")
        data, digest = self.bundle()
        dest = a.unpack(data, digest, V, C, self.root / "cache")
        self.assertFalse((dest / "bin/deployment.key").exists())
        self.assertFalse((dest / "bin/ci").exists())
        files = fixture(self.root)
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("idp-metadata.xml", "not for release")
        files["lambda/supivpn-lambda.zip"] = buf.getvalue()
        release = json.loads(files["release.json"])
        release["artifacts"]["supivpn-lambda.zip"] = a.sha(buf.getvalue())
        files["release.json"] = json.dumps(release).encode()
        with self.assertRaises(ValueError):
            a.validate_payload(files)

    def test_rejects_corruption_wrong_version_commit_and_truncation(self):
        data, digest = self.bundle()
        for content, version, commit in ((data[:-10], V, C), (data + b"x", V, C),
                                         (data, "v1.2.4", C), (data, V, "b" * 40)):
            with self.subTest(version=version, commit=commit):
                with self.assertRaises(ValueError):
                    a.unpack(content, digest, version, commit, self.root / "cache")
        self.assertFalse((self.root / "cache").exists())

    def test_rejects_traversal_symlinks_hardlinks_duplicates_and_size(self):
        cases = [("../escape", tarfile.REGTYPE, 0), ("/absolute", tarfile.REGTYPE, 0),
                 ("LICENSE", tarfile.SYMTYPE, 0), ("LICENSE", tarfile.LNKTYPE, 0),
                 ("LICENSE", tarfile.REGTYPE, a.MAX_FILE + 1)]
        for name, kind, size in cases:
            buf = io.BytesIO()
            with tarfile.open(fileobj=buf, mode="w:gz") as archive:
                header = tarfile.TarInfo(name)
                header.type, header.size, header.linkname = kind, size, "outside"
                if size == 0:
                    archive.addfile(header)
            if size:
                buf = io.BytesIO(gzip.compress(header.tobuf() + b"\0" * 1024))
            with self.assertRaises((ValueError, tarfile.TarError)):
                a.unpack(buf.getvalue(), a.sha(buf.getvalue()), V, C, self.root / "cache")
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as archive:
            archive.addfile(tarfile.TarInfo("LICENSE"), io.BytesIO())
            archive.addfile(tarfile.TarInfo("LICENSE"), io.BytesIO())
        with self.assertRaises(ValueError):
            a.unpack(buf.getvalue(), a.sha(buf.getvalue()), V, C, self.root / "cache")

    def test_rejects_stale_migrations_and_artifacts_and_input_symlink(self):
        files = fixture(self.root)
        files["migrations/001_initial.sql"] += b"-- changed"
        with self.assertRaises(ValueError):
            a.validate_payload(files)
        files = fixture(self.root)
        files["bin/supivpn"] += b"x"
        with self.assertRaises(ValueError):
            a.validate_payload(files)
        (self.root / "LICENSE").unlink()
        (self.root / "LICENSE").symlink_to(self.root / "THIRD_PARTY_NOTICES.md")
        with self.assertRaises(ValueError):
            self.bundle()

    def test_no_overwrite_existing_version(self):
        self.bundle()
        with self.assertRaises(ValueError):
            self.bundle()

    def test_invalid_identity_project_and_duplicate_json(self):
        for version in ("latest", "../v1.2.3", "v01.2.3"):
            with self.assertRaises(ValueError):
                a.identity(version, C)
        with self.assertRaises(ValueError):
            a.json_object(b'{"format":1,"format":2}')

    @staticmethod
    def archive(files):
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode="w:gz") as archive:
            for name, value in files.items():
                entry = tarfile.TarInfo(name)
                entry.size = len(value)
                archive.addfile(entry, io.BytesIO(value))
        return output.getvalue()

    def test_unknown_and_mixed_formats_are_rejected_before_extraction(self):
        files = fixture(self.root)
        for version, payload in ((1, files), (2, files), (4, files), (True, files), (3.0, files),
                                 (3, dict(files, **{"runtime/local/supivpn": b"extra"}))):
            with self.subTest(format=version):
                metadata = {"format": version, "version": V, "commit": C, "target": "linux-arm64",
                            "files": {name: {"sha256": a.sha(value), "size": len(value)}
                                      for name, value in payload.items()}}
                data = self.archive(dict(payload, **{"bundle.json": json.dumps(metadata).encode()}))
                cache = self.root / "refused-cache"
                with self.assertRaises(ValueError):
                    a.unpack(data, a.sha(data), V, C, cache)
                self.assertFalse(cache.exists())

    def test_source_to_bundle_mapping_is_explicit_and_build_paths_do_not_leak(self):
        files = fixture(self.root)
        for name in files:
            self.assertTrue((self.root / a.source_path(name)).is_file())
        data, digest = self.bundle()
        result = a.unpack(data, digest, V, C, self.root / "format-three-cache")
        metadata = a.json_object((result / "bundle.json").read_bytes())
        self.assertEqual(metadata["format"], 3)
        self.assertEqual(set(metadata["files"]), set(files))
        self.assertFalse(any(name.startswith(("runtime/", "local/", "internal/")) for name in metadata["files"]))
        for name in ("../escape", "local/credentials", "migrations/../../escape", "bin/unknown"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                a.source_path(name)


    def test_both_targets_roundtrip_and_wrong_target_is_rejected(self):
        for arch in ("arm64", "amd64"):
            with self.subTest(arch=arch):
                fixture(self.root, arch)
                bundle, digest = a.package(self.root, V, C, self.root / arch, arch=arch)
                result = a.unpack(bundle.read_bytes(), digest, V, C, self.root / "arch-cache", arch=arch)
                self.assertEqual(json.loads((result / "bundle.json").read_bytes())["target"], "linux-" + arch)
                self.assertEqual((result / "bin/supivpn").read_bytes()[18:20],
                                 b"\xb7\x00" if arch == "arm64" else b"\x3e\x00")
                other = "amd64" if arch == "arm64" else "arm64"
                with self.assertRaises(a.ValidationError):
                    a.unpack(bundle.read_bytes(), digest, V, C, self.root / "wrong-cache", arch=other)
        self.assertFalse((self.root / "wrong-cache").exists())

    def test_rehashed_mixed_architecture_payload_is_rejected(self):
        files = fixture(self.root)
        executable = bytearray(files["bin/supivpn"])
        executable[18:20] = b"\x3e\x00"
        files["bin/supivpn"] = bytes(executable)
        manifest = json.loads(files["release.json"])
        manifest["artifacts"]["supivpn"] = a.sha(files["bin/supivpn"])
        files["release.json"] = json.dumps(manifest).encode()
        with self.assertRaisesRegex(a.ValidationError, "architecture"):
            a.validate_payload(files, "arm64")

    def test_invalid_architecture_does_not_create_outputs(self):
        for arch in ("aarch64", "x86_64", "../amd64", "", "arm64 amd64"):
            with self.subTest(arch=arch), self.assertRaises(a.ValidationError):
                a.package(self.root, V, C, self.root / "invalid", arch=arch)
        self.assertFalse((self.root / "invalid").exists())

    @unittest.skipUnless(os.environ.get("SUPIVPN_TEST_BUILT_BUNDLE") == "1", "opt-in built artifact check")
    def test_real_built_artifacts_pack_and_verify(self):
        source = Path(__file__).resolve().parents[1]
        for arch in a.ARCHITECTURES:
            target, digest = a.package(source, "v0.0.0-local", "0" * 40, self.root / arch, arch=arch)
            dest = a.unpack(target.read_bytes(), digest, "v0.0.0-local", "0" * 40, self.root / "real-cache", arch=arch)
            self.assertTrue((dest / "lambda/supivpn-lambda.zip").is_file())


if __name__ == "__main__":
    unittest.main()
