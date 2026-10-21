# Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
# Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
# SPDX-License-Identifier: AGPL-3.0-only
import contextlib
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import zipfile

import artifacts as a
import github_release as release
import source_archive
from test_artifacts import fixture, V, C
from test_release_notes import signed_tag
from test_tag_release import result

OID = "b" * 40
RUN = {"id": 42, "run_attempt": 2, "path": ".github/workflows/checks.yml", "head_sha": C,
       "head_branch": V, "event": "push", "status": "completed", "conclusion": "success",
       "repository": {"full_name": "SupiVPN/supivpn"}, "head_repository": {"full_name": "SupiVPN/supivpn"}}
SOURCE = {"LICENSE": (b"AGPL test fixture", 0o644), "Makefile": (b"all:\n", 0o644)}


def source_tar(changes=None):
    files = {name: raw for name, (raw, _) in SOURCE.items()}
    files.update({"vendor/modules.txt": b"test module", "third-party/go/LICENSE": b"test notice"})
    files.update(changes or {})
    metadata = {"format": 1, "commit": C, "license": "AGPL-3.0-only",
                "files": {name: a.sha(raw) for name, raw in files.items()}}
    files["SOURCE.json"] = json.dumps(metadata).encode()
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        for name, raw in files.items():
            info = tarfile.TarInfo("supivpn/" + name)
            info.size, info.mode = len(raw), 0o644
            archive.addfile(info, io.BytesIO(raw))
    return buffer.getvalue()


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve())
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        files = fixture(self.root)
        self.sources = {name: raw for name, raw in files.items() if name not in a.BUILT_FILES}
        self.candidates = {}
        for arch in a.ARCHITECTURES:
            fixture(self.root, arch)
            target, digest = a.package(self.root, V, C, self.root / arch, arch=arch)
            data = {target.name: target.read_bytes(), "SHA256SUMS": (digest + "  " + target.name + "\n").encode()}
            record = {"format": 2, "repository": "SupiVPN/supivpn", "commit": C, "arch": arch,
                      "version": V, "tag": OID,
                      "run_id": 42, "run_attempt": 2, "filename": target.name, "sha256": digest}
            if arch == "arm64":
                name = "supivpn-source-" + C + ".tar.gz"
                data[name] = source_tar()
                record["source"] = {"filename": name, "sha256": a.sha(data[name])}
            data["candidate.json"] = json.dumps(record).encode()
            self.candidates[arch] = (data, record)

    def prepared(self, provenance=None):
        output = self.root / "prepared"
        notes = release.release_notes.generate(V, C, C + "\tImprove release verification\n")
        with patch.object(release, "ROOT", self.root), \
                patch.object(release.release_identity, "release_identity", return_value=(C, OID)), \
                patch.object(release, "select_run", return_value=RUN), \
                patch.object(release.release_identity, "release_sources", return_value=self.sources), \
                patch.object(source_archive, "source_files", return_value=SOURCE), \
                patch.object(release, "fetch_candidate", side_effect=lambda run, commit, version, oid, arch: self.candidates[arch]), \
                patch.object(release, "verify_provenance", side_effect=provenance or self.check_provenance) as attest, \
                patch.object(release.tag, "git", return_value=result(out=signed_tag(V, C, notes))), \
                contextlib.redirect_stdout(io.StringIO()):
            release.prepare(V, output)
        self.assertEqual(attest.call_count, 3)
        return output

    def check_provenance(self, path, commit, version, run):
        self.assertEqual((commit, version, run), (C, V, RUN))
        expected = {name: raw for files, _ in self.candidates.values() for name, raw in files.items()
                    if name.endswith(".tar.gz")}
        self.assertEqual(path.read_bytes(), expected[path.name])

    def test_source_provenance_failure_stops_before_unpacking_or_preparing_manifest(self):
        def reject_source(path, *args):
            if path.name.startswith("supivpn-source-"):
                raise a.ValidationError("Source provenance rejected")
        with patch.object(a, "unpack") as unpack, self.assertRaises(a.ValidationError):
            self.prepared(reject_source)
        unpack.assert_not_called()
        self.assertFalse((self.root / "prepared/SHA256SUMS").exists())
        self.assertFalse((self.root / "prepared/release-metadata.json").exists())

    def test_second_architecture_provenance_failure_does_not_prepare_a_release(self):
        def reject_amd64(path, *args):
            if "linux-amd64" in path.name:
                raise a.ValidationError("AMD64 provenance rejected")
        with self.assertRaises(a.ValidationError):
            self.prepared(reject_amd64)
        self.assertFalse((self.root / "prepared/SHA256SUMS").exists())
        self.assertFalse((self.root / "prepared/release-metadata.json").exists())

    def test_prepare_preserves_binaries_and_attaches_matching_source(self):
        output = self.prepared()
        metadata = release.checked_release(output, V)
        self.assertEqual(metadata["run_attempt"], 2)
        self.assertIn("  release-notes.md\n", (output / "SHA256SUMS").read_text())
        for arch in a.ARCHITECTURES:
            name = a.filename(V, arch)
            self.assertEqual((output / name).read_bytes(), self.candidates[arch][0][name])
            bundle = a.unpack((output / name).read_bytes(), metadata["assets"][name], V, C,
                              self.root / "verified", expected_sources=self.sources, arch=arch)
            self.assertEqual((bundle / "bin/supivpn").read_bytes(),
                             (self.root / a.source_path("bin/supivpn", arch)).read_bytes())
        (output / "release-notes.md").write_text("tampered")
        with self.assertRaises(a.ValidationError):
            release.checked_release(output, V)

    def test_candidate_zip_checks_attempt_identity_and_exact_file_set(self):
        files, _ = self.candidates["arm64"]
        def zipped(entries):
            output = io.BytesIO()
            with zipfile.ZipFile(output, "w") as archive:
                for name, data in entries.items():
                    archive.writestr(name, data)
            return output.getvalue()
        release.candidate_zip(zipped(files), "arm64", C, V, OID, RUN)
        for changed, run in ((dict(files, extra=b"x"), RUN), (files, dict(RUN, run_attempt=3)),
                             (dict(files, **{"SHA256SUMS": b"bad"}), RUN)):
            with self.assertRaises(a.ValidationError):
                release.candidate_zip(zipped(changed), "arm64", C, V, OID, run)
        for version, oid in (("v9.9.9", OID), (V, "c" * 40)):
            with self.assertRaises(a.ValidationError):
                release.candidate_zip(zipped(files), "arm64", C, version, oid, RUN)

    def test_source_archive_refuses_traversal_changes_and_missing_dependencies(self):
        raw = source_tar()
        source_archive.verify(raw, a.sha(raw), C, SOURCE)
        for changes in ({"../outside": b"x"}, {"LICENSE": b"changed"}, {"extra": b"x"}):
            raw = source_tar(changes)
            with self.assertRaises(a.ValidationError):
                source_archive.verify(raw, a.sha(raw), C, SOURCE)
        with self.assertRaises(a.ValidationError):
            source_archive.verify(raw, "0" * 64, C, SOURCE)

    def test_source_pack_accepts_sdk_root_alias_but_preserves_archive_checks(self):
        sdk = self.root / "sdk" / "libexec"
        (sdk / "src").mkdir(parents=True)
        (sdk.parent / "LICENSE").write_bytes(b"test notice")
        alias = self.root / "sdk-alias"
        alias.symlink_to(sdk, target_is_directory=True)
        def command(root, args, **kwargs):
            if args[:3] == ["go", "mod", "vendor"]:
                vendor = Path(args[-1])
                vendor.mkdir()
                (vendor / "modules.txt").write_bytes(b"test module")
                return b""
            if args[:2] == ["git", "diff"]:
                return b""
            if args == ["go", "env", "GOROOT"]:
                return str(alias).encode()
            if args == ["go", "version"]:
                return b"go version go1.27.2 linux/arm64"
            self.fail("Unexpected build command")
        with patch.object(source_archive, "source_files", return_value=dict(SOURCE)), \
                patch.object(source_archive, "command", side_effect=command):
            archive, digest = source_archive.pack(self.root, C, self.root / "source")
        source_archive.verify(archive.read_bytes(), digest, C, SOURCE)

    def test_publication_is_retryable_but_never_overwrites_conflicting_assets(self):
        output = self.prepared()
        metadata = release.checked_release(output, V)
        (output / "SHA256SUMS.asc").write_text("synthetic signature")
        metadata["assets"]["SHA256SUMS.asc"] = a.sha(b"synthetic signature")
        page = {"id": 1, "tag_name": V, "name": "SupiVPN " + V,
                "body": (output / "release-notes.md").read_text(), "prerelease": False,
                "draft": True, "assets": []}
        writes = []
        def api(path, method="GET", data=None, missing=False):
            if path == "git/ref/tags/" + V:
                return {"object": {"type": "tag", "sha": OID}}
            if path == "actions/runs/42":
                return RUN
            if path in {"releases/tags/" + V, "releases/1"}:
                if method == "PATCH":
                    writes.append(method)
                    page.update(data)
                return page
            self.fail("Unexpected API operation: " + path)
        def upload(url, method, data):
            self.assertEqual(method, "POST")
            name = url.split("?name=")[1]
            record = {"id": len(page["assets"]) + 1, "name": name, "state": "uploaded",
                      "size": len(data), "digest": "sha256:" + a.sha(data)}
            writes.append(name)
            page["assets"].append(record)
            return 201, json.dumps(record).encode()
        with patch.object(release.gh, "api", side_effect=api), \
                patch.object(release.gh, "request", side_effect=upload), \
                patch.object(release.artifact_signing, "verify"), contextlib.redirect_stdout(io.StringIO()):
            release.publish(V, output)
            self.assertEqual(len(writes), len(metadata["assets"]) + 1)
            writes.clear()
            release.publish(V, output)
            self.assertEqual(writes, [])
            original = list(page["assets"])
            for records in (original + [original[0]], original + [{"name": "unexpected"}]):
                with self.subTest(records=len(records)):
                    page["assets"] = records
                    with self.assertRaisesRegex(a.ValidationError, "Unexpected published assets"):
                        release.publish(V, output)
                    self.assertEqual(writes, [])
            page["assets"] = original
            page["assets"][0]["digest"] = "sha256:" + "0" * 64
            with self.assertRaises(a.ValidationError):
                release.publish(V, output)
            self.assertEqual(writes, [])

    def test_publication_refuses_unsigned_or_invalid_signature_before_remote_writes(self):
        output = self.prepared()
        with patch.object(release.gh, "api") as api, self.assertRaises(a.ValidationError):
            release.publish(V, output)
        api.assert_not_called()
        (output / "SHA256SUMS.asc").write_bytes(b"invalid signature")
        with patch.object(release.artifact_signing, "verify", side_effect=a.ValidationError("bad signature")), \
                patch.object(release.gh, "api") as api, self.assertRaises(a.ValidationError):
            release.publish(V, output)
        api.assert_not_called()

    def test_manifest_must_cover_notes_even_when_metadata_hash_is_replaced(self):
        output = self.prepared()
        manifest = output / "SHA256SUMS"
        manifest.write_text("\n".join(line for line in manifest.read_text().splitlines()
                                      if not line.endswith("  release-notes.md")) + "\n")
        path = output / "release-metadata.json"
        metadata = json.loads(path.read_text())
        metadata["assets"]["SHA256SUMS"] = a.sha(manifest.read_bytes())
        path.write_text(json.dumps(metadata))
        with self.assertRaises(a.ValidationError):
            release.checked_release(output, V)

    def test_tag_provenance_rejects_main_other_tags_forks_prs_and_failed_runs(self):
        self.assertTrue(release.valid_run(RUN, C, V))
        for changes in ({"conclusion": "failure"}, {"event": "pull_request"}, {"head_sha": "d" * 40},
                        {"head_branch": "main"}, {"head_branch": "v9.9.9"},
                        {"head_repository": {"full_name": "other/fork"}},
                        {"path": ".github/workflows/other.yml"}, {"run_attempt": 0}):
            self.assertFalse(release.valid_run(dict(RUN, **changes), C, V))

    def test_select_run_never_falls_back_to_main_or_another_tag_at_the_same_sha(self):
        bad = [dict(RUN, head_branch="main"), dict(RUN, head_branch="v9.9.9")]
        with patch.object(release.gh, "api", return_value={"workflow_runs": bad}), \
                self.assertRaises(a.ValidationError):
            release.select_run(C, V)
        with patch.object(release.gh, "api", return_value={"workflow_runs": bad + [RUN]}) as api:
            self.assertEqual(release.select_run(C, V), RUN)
        self.assertIn("event=push&status=success&head_sha=" + C, api.call_args.args[0])

    def test_accepts_actions_checkout_origin_and_refuses_foreign_or_multiple_origins(self):
        with patch.object(release.tag, "ORIGIN", release.tag.ORIGIN):
            for url in release.tag.GITHUB_ORIGINS:
                with patch.object(release.tag, "git", return_value=result(out=url + "\n")):
                    release.configure_origin()
                    self.assertEqual(release.tag.ORIGIN, url)
            for urls in ("https://github.com/other/fork", "https://github.com/SupiVPN/supivpn.evil",
                         "https://github.com/SupiVPN/supivpn\nhttps://github.com/other/fork"):
                with patch.object(release.tag, "git", return_value=result(out=urls)), self.assertRaises(a.ValidationError):
                    release.configure_origin()
