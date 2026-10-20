# Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
# Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
# SPDX-License-Identifier: AGPL-3.0-only
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import artifacts as a
import artifact_signing as signing


class FailureDiagnosticTests(unittest.TestCase):
    def test_only_allowlisted_status_names_and_numeric_codes_are_reported(self):
        private_text = b"synthetic-sensitive-payload"
        diagnostic = signing.failure_detail(
            b"gpg: " + private_text + b"\n"
            b"[GNUPG:] IMPORT_PROBLEM 0 " + private_text + b"\n"
            b"[GNUPG:] ERROR " + private_text + b" 67108949\n"
            b"[GNUPG:] FAILURE " + private_text + b" 67108949\n"
            b"[GNUPG:] BAD_PASSPHRASE " + private_text + b"\n"
            b"[GNUPG:] UNKNOWN_STATUS " + private_text + b"\n"
        )
        self.assertEqual(diagnostic,
                         "status=BAD_PASSPHRASE,IMPORT_PROBLEM; gpg-errors=67108949")
        self.assertNotIn(private_text.decode(), diagnostic)

    def test_malformed_and_freeform_diagnostics_cannot_escape(self):
        for stderr in (
            b"gpg: arbitrary sensitive text",
            b"[GNUPG:] FAILURE arbitrary sensitive-text",
            b"[GNUPG:] ERROR arbitrary -1",
            b"[GNUPG:] ERROR arbitrary 4294967296",
            b"[GNUPG:] ERROR arbitrary " + b"9" * 10000,
            b"[GNUPG:] ERROR arbitrary 123 extra",
            b"[GNUPG:] \xff sensitive-text",
            b"",
        ):
            with self.subTest(stderr=stderr[:40]):
                self.assertEqual(signing.failure_detail(stderr),
                                 "no recognized GnuPG failure status")

    def test_failed_import_reports_stage_without_echoing_input_or_child_output(self):
        private = "-----BEGIN PGP PRIVATE KEY BLOCK-----\nsynthetic-private-material"
        password = "test-only-passphrase"
        with tempfile.TemporaryDirectory() as directory:
            manifest = Path(directory).resolve() / "SHA256SUMS"
            manifest.write_bytes(b"synthetic test")
            failed = subprocess.CompletedProcess([], 2, private.encode(), (
                password + "\n[GNUPG:] IMPORT_PROBLEM 0 synthetic-key\n"
            ).encode())
            with patch.dict(os.environ, {signing.KEY_ENV: private, signing.PASSPHRASE: password}), \
                    patch.object(signing.subprocess, "run", return_value=failed), \
                    self.assertRaisesRegex(a.ValidationError, "at key-import: status=IMPORT_PROBLEM") as caught:
                signing.sign(manifest, {})
            self.assertNotIn(private, str(caught.exception))
            self.assertNotIn(password, str(caught.exception))
            self.assertFalse(manifest.with_name("SHA256SUMS.asc").exists())


class InventoryTests(unittest.TestCase):
    def test_private_primary_other_subkey_and_hardware_reference_are_rejected(self):
        primary, ci, tag = "A" * 40, "B" * 40, "C" * 40
        policy = {"release_signers": [primary], "artifact_signing_subkeys": [ci],
                  "tag_signing_subkeys": [tag]}
        def record(kind, fpr, availability, usage):
            row = [""] * 16
            row[0], row[11], row[14] = kind, usage, availability
            return ":".join(row) + "\nfpr:::::::::" + fpr + ":\n"
        stub = record("sec", primary, "#", "cSC")
        sub = record("ssb", ci, "+", "s")
        self.assertEqual(signing.secret_subkey(stub + sub, policy), ci)
        for text in (
            record("sec", primary, "+", "cSC") + sub,
            stub + record("ssb", tag, "+", "s"),
            stub + sub + record("ssb", tag, "+", "s"),
            stub + record("ssb", ci, "hardware", "s"),
            stub + record("ssb", ci, "+", "sa"),
            stub, sub, "",
        ):
            with self.subTest(text=text), self.assertRaises(a.ValidationError):
                signing.secret_subkey(text, policy)


@unittest.skipUnless(shutil.which("gpg") and shutil.which("gpgconf"), "GnuPG required")
class RealSigningTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Keep Unix agent socket paths below macOS's length limit.
        cls.temp = tempfile.TemporaryDirectory(prefix="supivpn-sign-test-", dir="/tmp")
        cls.root = Path(cls.temp.name).resolve()
        cls.home = cls.root / "gnupg"
        cls.home.mkdir(mode=0o700)
        cls.addClassCleanup(cls.cleanup_keyring)
        cls.password = "test-passphrase"
        cls.gpg("--pinentry-mode", "loopback", "--passphrase-fd", "0",
                "--quick-generate-key", "Release Test <test@example.invalid>", "ed25519", "cert", "1d",
                data=(cls.password + "\n").encode())
        cls.primary = cls.fingerprints()[0]
        for _ in range(2):
            cls.gpg("--pinentry-mode", "loopback", "--passphrase-fd", "0",
                    "--quick-add-key", cls.primary, "ed25519", "sign", "1d",
                    data=(cls.password + "\n").encode())
        cls.primary, cls.tagkey, cls.cikey = cls.fingerprints()
        cls.policy = {"release_signers": [cls.primary], "tag_signing_subkeys": [cls.tagkey],
                      "artifact_signing_subkeys": [cls.cikey]}
        cls.private = cls.gpg(
            "--pinentry-mode", "loopback", "--passphrase-fd", "0", "--armor",
            "--export-secret-subkeys", cls.cikey + "!", data=(cls.password + "\n").encode(),
        ).decode()
        cls.full = cls.gpg(
            "--pinentry-mode", "loopback", "--passphrase-fd", "0", "--armor",
            "--export-secret-keys", cls.primary, data=(cls.password + "\n").encode(),
        ).decode()

    @classmethod
    def gpg(cls, *args, data=None):
        proc = subprocess.run(["gpg", "--no-options", "--homedir", str(cls.home), "--batch", *args],
                              input=data, capture_output=True, timeout=60)
        if proc.returncode:
            raise RuntimeError("Disposable GnuPG fixture operation failed")
        return proc.stdout

    @classmethod
    def fingerprints(cls):
        return [line.split(":")[9] for line in cls.gpg("--with-colons", "--list-keys").decode().splitlines()
                if line.startswith("fpr:")]

    @classmethod
    def cleanup_keyring(cls):
        subprocess.run(["gpgconf", "--homedir", str(cls.home), "--kill", "gpg-agent"],
                       capture_output=True, timeout=15)
        cls.temp.cleanup()

    def test_sign_verify_tamper_and_role_separation(self):
        with tempfile.TemporaryDirectory(dir=self.root) as directory:
            manifest = Path(directory) / "SHA256SUMS"
            original = ("a" * 64 + "  supivpn-v1.0.0-linux-arm64.tar.gz\n").encode()
            manifest.write_bytes(original)
            with patch.dict(os.environ, {signing.KEY_ENV: self.private, signing.PASSPHRASE: self.password}):
                target = signing.sign(manifest, self.policy)
                self.assertNotIn(signing.KEY_ENV, os.environ)
                self.assertNotIn(signing.PASSPHRASE, os.environ)
            signing.verify(manifest, target, self.policy, home=self.home)
            with self.assertRaises(a.ValidationError):
                signing.verify(manifest, target, dict(self.policy, artifact_signing_subkeys=[self.tagkey]), home=self.home)
            manifest.write_bytes(original + b"changed")
            with self.assertRaises(a.ValidationError):
                signing.verify(manifest, target, self.policy, home=self.home)
            manifest.write_bytes(original)
            target.write_bytes(b"invalid")
            with self.assertRaises(a.ValidationError):
                signing.verify(manifest, target, self.policy, home=self.home)

    def test_full_primary_and_wrong_passphrase_never_produce_a_signature(self):
        for private, password in ((self.full, self.password), (self.private, "wrong-test-passphrase")):
            with tempfile.TemporaryDirectory(dir=self.root) as directory:
                manifest = Path(directory) / "SHA256SUMS"
                manifest.write_bytes(b"synthetic test")
                with patch.dict(os.environ, {signing.KEY_ENV: private, signing.PASSPHRASE: password}), \
                        self.assertRaises(a.ValidationError) as caught:
                    signing.sign(manifest, self.policy)
                if private == self.private:
                    self.assertIn("at checksum-signing:", str(caught.exception))
                    self.assertNotIn(password, str(caught.exception))
                self.assertFalse(manifest.with_name("SHA256SUMS.asc").exists())
