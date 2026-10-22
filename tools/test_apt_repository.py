# Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
# SPDX-License-Identifier: AGPL-3.0-only
"""Release selection and real APT signature/index/package verification in Debian."""
from functools import partial
import hashlib
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import io
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
from threading import Thread
import unittest
from unittest.mock import patch

import artifacts as a
import apt_repository as repo
import artifact_signing as signing
import test_artifact_signing as keys


# Public-only synthetic certificate; its disposable private keys were discarded.
# Both subkey fingerprints start with letters, so GnuPG's numeric comparison
# treats them as zero. No expiration keeps this regression independent of time.
FILTER_PUBLIC_KEY = b"""-----BEGIN PGP PUBLIC KEY BLOCK-----

mDMEato2oRYJKwYBBAHaRw8BAQdAg/TBGrFG+ZikMtfTcNI7Uz9kmxGyv9GslBGK
jplbG1S0KkFQVCBSZWdyZXNzaW9uIFRlc3QgPHRlc3RAZXhhbXBsZS5pbnZhbGlk
PoiQBBMWCgA4FiEEyowdtSNHIGlreYDDxDdYppae1PUFAmraNqECGwEFCwkIBwIG
FQoJCAsCBBYCAwECHgECF4AACgkQxDdYppae1PXyrAD/YE0hkag/06FEaYDAp/es
hLwmVOtWI2UDk3blLR/mgN0BANqYuEj8w22nT9WtAvFoy6ArYKlMu2oS7Dd8bdgF
hwgCuDMEato2oRYJKwYBBAHaRw8BAQdAwJ7VDanAOQa4Bi1fwGPcmX1CXRZ/Xn90
QOv1BAD2CqWI7wQYFgoAIBYhBMqMHbUjRyBpa3mAw8Q3WKaWntT1BQJq2jahAhsC
AIEJEMQ3WKaWntT1diAEGRYKAB0WIQS0uZz6DoJRKbCbKVYZXjYzA+I+DgUCato2
oQAKCRAZXjYzA+I+Dn8qAQCRaO4yqiV1FpU4uofzDyTJFtRKYdkRUs3HrBtui45V
ugD/XDmLO9O4HiVoi2j7w3+LE2XKz2CSg7R4Yr0moSngWwESVwD9EHNFh8W6b5S+
zraodJ/GtbJJwwqTXrbZW6sY148AuaQA/ihNvV6iqVSlTt4uBaz3qeUhyMHx+69V
msMw1UWfk0ULuDMEato2oRYJKwYBBAHaRw8BAQdA/RwGbmTuyNesb9trmXIe6L1Q
GDIedggiSUM5A54yqlqI7wQYFgoAIBYhBMqMHbUjRyBpa3mAw8Q3WKaWntT1BQJq
2jahAhsCAIEJEMQ3WKaWntT1diAEGRYKAB0WIQTHnhvubZvhHMHM8B0oZW1p5lvJ
QQUCato2oQAKCRAoZW1p5lvJQQX9AQCfDNgkaOqr222Y69zzL7VS1qncPxl4q4ts
4QoBucweHQD9E8y4fM+S1i0wrrnunKtcKfdddr8JD5QZF2HIeGjigQR9rwD/dQdF
65iFQdTn0yLfr/xT99vwSFHBZ7LiFVHzuBssA8UBANTGahwWdBrF7FcaFKKAuZv8
mvASGC/n+YuqSl96DIkE
=eC0d
-----END PGP PUBLIC KEY BLOCK-----
"""
FILTER_PRIMARY = "CA8C1DB5234720696B7980C3C43758A6969ED4F5"
FILTER_SUBKEYS = ("B4B99CFA0E825129B09B2956195E363303E23E0E",
                  "C79E1BEE6D9BE11CC1CCF01D28656D69E65BC941")


@unittest.skipUnless(shutil.which("gpg"), "GnuPG required")
class PublicKeyTests(unittest.TestCase):
    def test_selects_exact_subkey_when_numeric_fingerprints_collide(self):
        for selected in FILTER_SUBKEYS:
            with self.subTest(selected=selected), tempfile.TemporaryDirectory() as home:
                policy = {"release_signers": [FILTER_PRIMARY], "artifact_signing_subkeys": [selected]}
                public = repo.apt_public_key(FILTER_PUBLIC_KEY, policy)
                result = subprocess.run(
                    ["gpg", "--no-options", "--homedir", home, "--batch", "--no-autostart",
                     "--with-colons", "--show-keys"], input=public, capture_output=True, timeout=30)
                self.assertEqual(result.returncode, 0)
                fingerprints = [line.split(":")[9] for line in result.stdout.decode().splitlines()
                                if line.startswith("fpr:")]
                self.assertEqual(fingerprints, [FILTER_PRIMARY, selected])

    def test_missing_primary_or_subkey_is_refused(self):
        for primary, subkey in (("A" * 40, FILTER_SUBKEYS[0]), (FILTER_PRIMARY, "D" * 40)):
            with self.subTest(primary=primary, subkey=subkey), self.assertRaises(a.ValidationError):
                repo.apt_public_key(FILTER_PUBLIC_KEY,
                                    {"release_signers": [primary], "artifact_signing_subkeys": [subkey]})


def record(version, *, packages=True, **changes):
    return dict(tag_name=version, draft=False, prerelease=False,
                assets=[{"name": name} for name in (repo.package_names(version)
                        | {"SHA256SUMS", "SHA256SUMS.asc"})] if packages else [], **changes)


class SelectionTests(unittest.TestCase):
    def test_selects_two_previous_stable_releases_and_refuses_rollback(self):
        items = [record("v0.5.0", packages=False), record("v1.0.0"), record("v1.1.0"), record("v1.2.0"),
                 {"tag_name": "v2.0.0-rc.1", "draft": False, "prerelease": True},
                 {"tag_name": "v2.0.0", "draft": True}]
        with patch.object(repo.gh, "api", return_value=items):
            self.assertEqual([r["tag_name"] for r in repo.history("v1.3.0")], ["v1.1.0", "v1.2.0"])
            with self.assertRaisesRegex(a.ValidationError, "rollback"):
                repo.history("v1.1.0")
        with patch.object(repo.gh, "api", return_value=[record("v1.0.0"), record("v1.0.0")]):
            with self.assertRaisesRegex(a.ValidationError, "Duplicate"):
                repo.history("v1.1.0")

    def test_incomplete_release_and_prerelease_target_are_refused(self):
        item = record("v1.0.0")
        item["assets"] = [{"name": "supivpn_1.0.0_all.deb"}]
        with patch.object(repo.gh, "api", return_value=[item]):
            with self.assertRaisesRegex(a.ValidationError, "incomplete"):
                repo.history("v1.1.0")
        for version in ("v1.1.0-rc.1", "v01.2.3", "1.0.0", "../outside"):
            with self.assertRaises(a.ValidationError):
                repo.order(version)

    def test_site_size_links_and_unexpected_files_are_refused(self):
        with tempfile.TemporaryDirectory() as temp:
            site = Path(temp)
            (site / "file").write_bytes(b"test")
            with patch.object(repo, "MAX_SITE", 1), self.assertRaises(a.ValidationError):
                repo.tree(site)
            (site / "link").symlink_to("file")
            with self.assertRaises(a.ValidationError):
                repo.tree(site)


@unittest.skipUnless(all(shutil.which(name) for name in ("reprepro", "dpkg-deb", "apt-get", "gpg", "gpgconf")),
                     "Debian APT/reprepro/GnuPG required; use ci/apt/Dockerfile")
class AptIntegrationTests(unittest.TestCase):
    def setUp(self):
        def fixture_command(args):
            result = subprocess.run(args, capture_output=True, timeout=120)
            # Only synthetic reprepro/dpkg/APT fixture output; GPG uses its own runner.
            self.assertEqual(result.returncode, 0, (result.stdout + result.stderr).decode(errors="replace"))
            return result.stdout
        patcher = patch.object(repo, "command", side_effect=fixture_command)
        patcher.start()
        self.addCleanup(patcher.stop)

    @classmethod
    def setUpClass(cls):
        keys.RealSigningTests.setUpClass()
        cls.key = keys.RealSigningTests
        cls.addClassCleanup(cls.key.doClassCleanups)

    def packages(self, root, version):
        directory = root / version
        directory.mkdir()
        value = version[1:]
        for name, arches in (("supivpn", ("all",)), ("supivpn-node", ("amd64", "arm64")),
                             ("supivpn-controller", ("amd64", "arm64"))):
            for arch in arches:
                source = directory / (name + arch)
                (source / "DEBIAN").mkdir(parents=True)
                depends = (f"Depends: supivpn-node (= {value}), supivpn-controller (= {value})\n"
                           if name == "supivpn" else "")
                (source / "DEBIAN/control").write_text(
                    f"Package: {name}\nSource: supivpn\nVersion: {value}\nArchitecture: {arch}\n"
                    "Maintainer: Test <test@example.invalid>\nSection: net\nPriority: optional\n"
                    + depends + "Description: Disposable APT fixture\n")
                repo.command(["dpkg-deb", "--build", "--root-owner-group", str(source),
                              str(directory / f"{name}_{value}_{arch}.deb")])
        archive = directory / f"supivpn_{value}.tar.xz"
        with tarfile.open(archive, "w:xz") as target:
            data = b"Disposable Corresponding Source fixture\n"
            entry = tarfile.TarInfo("source/README")
            entry.size = len(data)
            target.addfile(entry, io.BytesIO(data))
        raw = archive.read_bytes()
        (directory / f"supivpn_{value}.dsc").write_text(
            f"Format: 3.0 (native)\nSource: supivpn\nBinary: supivpn, supivpn-node, supivpn-controller\n"
            f"Architecture: all amd64 arm64\nVersion: {value}\nMaintainer: Test <test@example.invalid>\n"
            f"Files:\n {hashlib.md5(raw).hexdigest()} {len(raw)} {archive.name}\n"
            f"Checksums-Sha256:\n {a.sha(raw)} {len(raw)} {archive.name}\n")
        return directory

    def test_signed_repository_updates_downloads_and_rejects_tampering(self):
        with tempfile.TemporaryDirectory(dir="/tmp", prefix="apt-test-") as temp:
            root = Path(temp)
            packages = [(v, self.packages(root, v)) for v in ("v1.0.0", "v1.1.0")]
            output = root / "apt"
            public = self.key.gpg("--armor", "--export", self.key.primary)
            repo.build(output, "v1.1.0", packages, public, self.key.policy)
            repo.validate(output, "v1.1.0", self.key.policy)
            site = output / "site"
            manifest = site / "dists/trixie/Release"
            with patch.dict(os.environ, {signing.KEY_ENV: self.key.private, signing.PASSPHRASE: self.key.password}):
                signing.sign(manifest, self.key.policy, apt=True)
            with patch.dict(os.environ, {"GNUPGHOME": str(self.key.home)}):
                repo.validate(output, "v1.1.0", self.key.policy, signed=True)
            signing.verify_inline(manifest, manifest.with_name("InRelease"), self.key.policy, home=self.key.home)
            with self.assertRaises(a.ValidationError):
                signing.verify_inline(manifest, manifest.with_name("InRelease"),
                                      dict(self.key.policy, artifact_signing_subkeys=[self.key.tagkey]), home=self.key.home)
            requests = []
            class Handler(SimpleHTTPRequestHandler):
                def log_message(self, *_):
                    pass
                def do_GET(self):
                    requests.append(self.path)
                    return super().do_GET()
            server = ThreadingHTTPServer(("127.0.0.1", 0), partial(Handler, directory=str(site)))
            worker = Thread(target=server.serve_forever, daemon=True)
            worker.start()
            self.addCleanup(server.server_close)
            self.addCleanup(server.shutdown)
            uri = f"http://127.0.0.1:{server.server_port}"
            keyfile = root / "public.asc"
            keyfile.write_bytes((site / "supivpn.asc").read_bytes())
            def client(name, arch):
                directory = root / name
                for path in ("var/lib/apt/lists/partial", "var/cache/apt/archives/partial", "etc/apt/apt.conf.d"):
                    (directory / path).mkdir(parents=True)
                (directory / "status").touch()
                (directory / "apt.conf").write_text(
                    f'Dir "{directory}";\nDir::Etc::parts "apt.conf.d";\nDir::Etc::main "apt.conf";\n')
                (directory / "supivpn.sources").write_text(repo.source_entry(self.key.policy, uri=uri, key=str(keyfile)))
                return ["env", "APT_CONFIG=" + str(directory / "apt.conf"), "apt-get", "-o", "Dir=" + str(directory),
                        "-o", "Dir::Etc::sourcelist=" + str(directory / "supivpn.sources"),
                        "-o", "Dir::Etc::sourceparts=-", "-o", "Dir::State::status=" + str(directory / "status"),
                        "-o", "APT::Architecture=" + arch, "-o", "APT::Sandbox::User=root",
                        "-o", "Acquire::Languages=none", "-o", "APT::Update::Error-Mode=any"]
            for arch in ("amd64", "arm64"):
                args = client(arch, arch)
                repo.command([*args, "update"])
                repo.command([*args, "--download-only", "--yes", "install", "supivpn"])
                downloaded = {p.name for p in (root / arch / "var/cache/apt/archives").glob("*.deb")}
                self.assertEqual(downloaded, {f"supivpn_1.1.0_all.deb", f"supivpn-node_1.1.0_{arch}.deb",
                                              f"supivpn-controller_1.1.0_{arch}.deb"})
            source_args = client("source-download", "amd64")
            source_list = root / "source-download/supivpn.sources"
            source_list.write_text(source_list.read_text().replace("Types: deb\n", "Types: deb deb-src\n"))
            repo.command([*source_args, "update"])
            source_result = subprocess.run([*source_args, "--download-only", "source", "supivpn"],
                                           cwd=root / "source-download", capture_output=True, timeout=60)
            self.assertEqual(source_result.returncode, 0, source_result.stderr.decode())
            for suffix in ("dsc", "tar.xz"):
                name = "supivpn_1.1.0." + suffix
                self.assertEqual((root / "source-download" / name).read_bytes(), (packages[-1][1] / name).read_bytes())
            self.assertTrue(any("/by-hash/SHA256/" in path for path in requests))
            self.assertTrue(list((site / "pool").rglob("supivpn_1.0.0_all.deb")))
            # Fetch authenticated indexes, then alter only a package: APT must refuse its bytes.
            args = client("bad-package", "amd64")
            repo.command([*args, "update"])
            package = next((site / "pool").rglob("supivpn-node_1.1.0_amd64.deb"))
            original = package.read_bytes()
            package.write_bytes(b"X" + original[1:])
            bad = subprocess.run([*args, "--download-only", "--yes", "install", "supivpn"], capture_output=True)
            self.assertNotEqual(bad.returncode, 0)
            self.assertIn(b"Hash Sum mismatch", bad.stderr)
            with self.assertRaises(a.ValidationError):
                repo.validate(output, "v1.1.0", self.key.policy, signed=True)
            package.write_bytes(original)
            inline = manifest.with_name("InRelease")
            inline.write_bytes(inline.read_bytes().replace(b"Origin: SupiVPN", b"Origin: FakeVPN"))
            args = client("bad-signature", "amd64")
            bad = subprocess.run([*args, "update"], capture_output=True)
            self.assertNotEqual(bad.returncode, 0)

    def test_previous_release_download_is_bound_to_signed_checksums(self):
        with tempfile.TemporaryDirectory(dir="/tmp") as temp:
            root = Path(temp)
            original = self.packages(root, "v1.0.0")
            files = {name: (original / name).read_bytes() for name in repo.package_names("v1.0.0")}
            files["SHA256SUMS"] = a.checksums({name: a.sha(raw) for name, raw in files.items()})
            sums = original / "SHA256SUMS"
            sums.write_bytes(files["SHA256SUMS"])
            with patch.dict(os.environ, {signing.KEY_ENV: self.key.private, signing.PASSPHRASE: self.key.password}):
                files["SHA256SUMS.asc"] = signing.sign(sums, self.key.policy).read_bytes()
            item = record("v1.0.0")
            item["assets"] = [{"id": index, "name": name, "size": len(raw), "state": "uploaded",
                               "digest": "sha256:" + a.sha(raw)} for index, (name, raw) in enumerate(files.items(), 1)]
            by_id = {str(entry["id"]): entry["name"] for entry in item["assets"]}
            def reply(url, **kwargs):
                self.assertTrue(url.startswith(repo.gh.API + "releases/assets/"))
                self.assertEqual(kwargs["accept"], "application/octet-stream")
                return 200, files[by_id[url.rsplit("/", 1)[1]]]
            with patch.object(repo.gh, "request", side_effect=reply), patch.dict(os.environ, {"GNUPGHOME": str(self.key.home)}):
                repo.download(item, root / "download", self.key.policy)
                name = "supivpn_1.0.0_all.deb"
                files[name] = b"X" + files[name][1:]
                with self.assertRaisesRegex(a.ValidationError, "checksum mismatch"):
                    repo.download(item, root / "tampered", self.key.policy)
            site = root / "site"
            (site / "pool").mkdir(parents=True)
            for name in repo.package_names("v1.0.0"):
                shutil.copyfile(original / name, site / "pool" / name)
            with patch.object(repo.gh, "api", return_value=item):
                repo.published("v1.0.0", site)
                item["draft"] = True
                with self.assertRaises(a.ValidationError):
                    repo.published("v1.0.0", site)
