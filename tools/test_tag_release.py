# Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
# Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
# SPDX-License-Identifier: AGPL-3.0-only
"""Release-tag guards with mocked Git/GPG; no real tags or network requests."""
import contextlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

import tag_release as tag
from test_release_notes import signed_tag

SHA = "a" * 40
MAIN = "b" * 40
KEY = "C" * 40
OTHER_KEY = "D" * 40
VERSION = "v0.1.0-rc.1"
REF = "refs/tags/" + VERSION
TAGKEY = "E" * 40
CIKEY = "F" * 40
POLICY = {"release_signers": [KEY], "tag_signing_subkeys": [TAGKEY], "artifact_signing_subkeys": [CIKEY]}
HISTORY = SHA + "\tImprove release delivery for operators.\n"
NOTES = tag.release_notes.generate(VERSION, SHA, HISTORY)
MAIN_HISTORY = MAIN + "\tImprove release delivery for operators.\n"
MAIN_NOTES = tag.release_notes.generate(VERSION, MAIN, MAIN_HISTORY)


def result(code=0, out="", err=""):
    return subprocess.CompletedProcess([], code, out, err)


def signed(key=KEY, subkey=TAGKEY):
    return result(err=f"[GNUPG:] VALIDSIG {subkey} 2026-09-24 1 0 4 0 1 10 00 {key}\n")


class TagTests(unittest.TestCase):
    def execute(self, overrides=None, version=VERSION, commit=SHA, env=None, current=POLICY):
        replies = {
            ("rev-parse", "--show-toplevel"): result(out=str(tag.ROOT) + "\n"),
            ("status", "--porcelain=v1", "--untracked-files=normal"): result(),
            ("remote", "get-url", "--all", "origin"): result(out=tag.ORIGIN + "\n"),
            ("remote", "get-url", "--push", "--all", "origin"): result(out=tag.ORIGIN + "\n"),
            ("show-ref", "--verify", "--quiet", REF): result(1),
            ("ls-remote", "--exit-code", "--refs", "origin", REF): result(2),
            ("fetch", "--no-tags", "origin", "refs/heads/main"): result(),
            ("rev-parse", "--verify", "FETCH_HEAD^{commit}"): result(out=MAIN + "\n"),
            ("cat-file", "-t", SHA): result(out="commit\n"),
            ("merge-base", "--is-ancestor", SHA, MAIN): result(),
            ("show", SHA + ":ci/signers.json"): result(out=json.dumps(POLICY)),
            ("ls-remote", "--tags", "--refs", "origin", "refs/tags/v*"): result(),
            ("log", "--no-show-signature", "--no-decorate", "--format=%H%x09%s",
             "--reverse", "--max-count=257", SHA, "--"): result(out=HISTORY),
            ("cat-file", "tag", REF): result(out=signed_tag(VERSION, SHA, NOTES)),
            ("verify-commit", "--raw", SHA): signed(),
            ("tag", "-s", "-u", TAGKEY + "!", "--cleanup=verbatim", "-F", "-", "--", VERSION, SHA): result(),
            ("verify-tag", "--raw", REF): signed(),
            ("rev-parse", "--verify", REF + "^{commit}"): result(out=SHA + "\n"),
        }
        if commit == "main":
            replies.update({
                ("cat-file", "-t", MAIN): result(out="commit\n"),
                ("merge-base", "--is-ancestor", MAIN, MAIN): result(),
                ("show", MAIN + ":ci/signers.json"): result(out=json.dumps(POLICY)),
                ("log", "--no-show-signature", "--no-decorate", "--format=%H%x09%s",
                 "--reverse", "--max-count=257", MAIN, "--"): result(out=MAIN_HISTORY),
                ("cat-file", "tag", REF): result(out=signed_tag(VERSION, MAIN, MAIN_NOTES)),
                ("verify-commit", "--raw", MAIN): signed(),
                ("tag", "-s", "-u", TAGKEY + "!", "--cleanup=verbatim", "-F", "-", "--", VERSION, MAIN): result(),
                ("rev-parse", "--verify", REF + "^{commit}"): result(out=MAIN + "\n"),
            })
        replies.update(overrides or {})
        calls = []

        def run(argv, **kwargs):
            self.assertEqual(argv[:9], ["git", "-c", "gpg.format=openpgp", "-c", "gpg.program=gpg",
                                      "-c", "gpg.openpgp.program=gpg", "-c", "core.fsmonitor=false"])
            self.assertEqual(kwargs["cwd"], tag.ROOT)
            self.assertEqual(kwargs["env"]["GIT_NO_REPLACE_OBJECTS"], "1")
            self.assertFalse(kwargs.get("shell", False))
            self.assertLessEqual(kwargs["timeout"], 180)
            command = tuple(argv[9:])
            calls.append(command)
            if command[0] == "tag":
                self.assertEqual(kwargs["input"], MAIN_NOTES if commit == "main" else NOTES)
                self.assertEqual(kwargs["env"]["GIT_COMMITTER_NAME"], "SupiVPN Releases")
                self.assertEqual(kwargs["env"]["GIT_COMMITTER_EMAIL"], "release@supivpn.com")
            else:
                self.assertIsNone(kwargs["input"])
            self.assertIn(command, replies, "Unexpected Git operation")
            response = replies[command]
            if isinstance(response, Exception):
                raise response
            return response

        output = io.StringIO()
        context = dict(SUPIVPN_TAG_VERSION=version, SUPIVPN_TAG_COMMIT=commit, **(env or {}))
        with mock.patch.dict(os.environ, context, clear=True), \
                mock.patch.object(tag.signatures, "read_policy", return_value=current), \
                mock.patch.object(tag.subprocess, "run", side_effect=run), \
                contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            code = tag.main()
        self.assertFalse(any(command[0] in {"push", "update-ref", "reset", "checkout"} for command in calls))
        return code, output.getvalue(), calls

    def test_creates_exact_signed_tag_only_after_all_preflight_checks(self):
        code, output, calls = self.execute()
        self.assertEqual(code, 0, output)
        self.assertEqual(calls[-4][0], "tag")
        self.assertNotIn(("verify-commit", "--raw", SHA), calls)
        self.assertIn("Local tag and authorized GPG signature verified", output)
        self.assertIn("git push origin " + REF, output)
        self.assertEqual(sum(c[0] == "tag" for c in calls), 1)

    def test_version_policy(self):
        for version in ("v0.1.0", "v1.2.3", "v2.0.0-rc.1", "v0.2.0-alpha.1", "v0.2.0-beta.2"):
            self.assertIsNotNone(tag.VERSION.fullmatch(version))
        for version in ("", "0.1.0", "v01.0.0", "v0.01.0", "v0.1.00", "v0.1.0-rc.01",
                        "v0.1.0-rc", "v0.1.0+build.1", "v1.2.3\n", "--force", "v1.2.3;touch sentinel",
                        "v" + "1" * 65 + ".0.0", "$(shell touch sentinel)"):
            with self.subTest(version=version):
                code, _, calls = self.execute(version=version)
                self.assertEqual(code, 1)
                self.assertEqual(calls, [])

    def test_main_selection_pins_the_fetched_sha_for_signing_and_verification(self):
        code, output, calls = self.execute(commit="main")
        self.assertEqual(code, 0, output)
        self.assertIn("Selected fetched main commit: " + MAIN, output)
        self.assertIn(("fetch", "--no-tags", "origin", "refs/heads/main"), calls)
        self.assertNotIn(("verify-commit", "--raw", MAIN), calls)
        self.assertEqual(calls[-4], ("tag", "-s", "-u", TAGKEY + "!", "--cleanup=verbatim", "-F", "-", "--", VERSION, MAIN))
        self.assertNotIn(("verify-commit", "--raw", SHA), calls)

    def test_main_fetch_failure_cannot_fall_back_to_an_older_commit(self):
        for command, response in (
            (("fetch", "--no-tags", "origin", "refs/heads/main"), result(1)),
            (("rev-parse", "--verify", "FETCH_HEAD^{commit}"), result(out="0" * 40)),
        ):
            with self.subTest(command=command):
                code, _, calls = self.execute({command: response}, commit="main")
                self.assertEqual(code, 1)
                self.assertFalse(any(c[0] == "tag" for c in calls))

    def test_requires_main_or_explicit_commit_and_local_operator(self):
        for commit in ("", "HEAD", "origin/main", "abc123", "0" * 40, "A" * 40, SHA + "\n"):
            with self.subTest(commit=commit):
                code, _, calls = self.execute(commit=commit)
                self.assertEqual(code, 1)
                self.assertEqual(calls, [])
        for key in ("CI", "GITHUB_ACTIONS"):
            code, _, calls = self.execute(env={key: "true"})
            self.assertEqual(code, 1)
            self.assertEqual(calls, [])

    def test_preflight_failures_never_create_a_tag(self):
        cases = [
            (("rev-parse", "--show-toplevel"), result(out="/not-this-checkout")),
            (("status", "--porcelain=v1", "--untracked-files=normal"), result(out=" M Makefile\n")),
            (("status", "--porcelain=v1", "--untracked-files=normal"), result(out="?? new.py\n")),
            (("remote", "get-url", "--all", "origin"), result(out="git@github.com:someone/fork.git\n")),
            (("remote", "get-url", "--push", "--all", "origin"), result(out=tag.ORIGIN + "\nother\n")),
            (("show-ref", "--verify", "--quiet", REF), result()),
            (("show-ref", "--verify", "--quiet", REF), result(128)),
            (("ls-remote", "--exit-code", "--refs", "origin", REF), result(out=SHA + "\t" + REF)),
            (("ls-remote", "--exit-code", "--refs", "origin", REF), result(128)),
            (("fetch", "--no-tags", "origin", "refs/heads/main"), result(1)),
            (("fetch", "--no-tags", "origin", "refs/heads/main"), subprocess.TimeoutExpired("git", 60)),
            (("rev-parse", "--verify", "FETCH_HEAD^{commit}"), result(out="not-a-commit")),
            (("cat-file", "-t", SHA), result(out="tag\n")),
            (("cat-file", "-t", SHA), result(128)),
            (("merge-base", "--is-ancestor", SHA, MAIN), result(1)),
            (("show", SHA + ":ci/signers.json"), result(out="{}")),
            (("ls-remote", "--tags", "--refs", "origin", "refs/tags/v*"), result(128)),
            (("ls-remote", "--tags", "--refs", "origin", "refs/tags/v*"), result(out="invalid record")),
            (("log", "--no-show-signature", "--no-decorate", "--format=%H%x09%s",
              "--reverse", "--max-count=257", SHA, "--"), result(out="invalid history")),
        ]
        for command, response in cases:
            with self.subTest(command=command, response=response):
                code, _, calls = self.execute({command: response})
                self.assertEqual(code, 1)
                self.assertFalse(any(c[0] == "tag" for c in calls))

    def test_generation_failure_creates_no_tag_and_withholds_raw_history(self):
        command = ("log", "--no-show-signature", "--no-decorate", "--format=%H%x09%s",
                   "--reverse", "--max-count=257", MAIN, "--")
        for response in (result(128, err="private diagnostic"), result(out="private diagnostic"),
                         subprocess.TimeoutExpired("git", 30, stderr="private diagnostic")):
            with self.subTest(response=response):
                code, output, calls = self.execute({command: response}, commit="main")
                self.assertEqual(code, 1)
                self.assertNotIn("private diagnostic", output)
                self.assertFalse(any(c[0] == "tag" for c in calls))

    def test_signing_or_verification_failure_preserves_tag_and_reports_uncertainty(self):
        cases = [
            (("tag", "-s", "-u", TAGKEY + "!", "--cleanup=verbatim", "-F", "-", "--", VERSION, SHA), result(1, err="private diagnostic")),
            (("tag", "-s", "-u", TAGKEY + "!", "--cleanup=verbatim", "-F", "-", "--", VERSION, SHA), subprocess.TimeoutExpired("git", 180)),
            (("verify-tag", "--raw", REF), result(1, err="private diagnostic")),
            (("verify-tag", "--raw", REF), signed(OTHER_KEY)),
            (("verify-tag", "--raw", REF), signed(KEY, CIKEY)),
            (("rev-parse", "--verify", REF + "^{commit}"), result(out=MAIN)),
            (("cat-file", "tag", REF), result(out=signed_tag(VERSION, SHA, NOTES + "\nChanged\n"))),
            (("cat-file", "tag", REF), result(out="private diagnostic")),
        ]
        for command, response in cases:
            with self.subTest(command=command):
                code, output, calls = self.execute({command: response})
                self.assertEqual(code, 1)
                self.assertIn("a local tag may exist", output)
                self.assertNotIn("private diagnostic", output)
                self.assertNotIn("git push origin", output)
                self.assertFalse(any("-d" in c or "-f" in c for c in calls))

    def test_tag_must_satisfy_separate_release_signer_lists(self):
        restricted = dict(POLICY, release_signers=[OTHER_KEY])
        for overrides, current in (({}, restricted),
                                   ({("show", SHA + ":ci/signers.json"): result(out=json.dumps(restricted))}, POLICY)):
            code, output, _ = self.execute(overrides, current=current)
            self.assertEqual(code, 1)
            self.assertIn("verify-tag", output)

class AutomaticNotesTests(unittest.TestCase):
    VERSION = "v1.0.0"
    BASE = "c" * 40
    OID = "d" * 40
    OTHER_OID = "e" * 40
    OTHER_BASE = "f" * 40

    def generate(self, records, overrides=None, signature_error=None):
        previous = "v0.9.0-rc.10"
        baseline = signed_tag(previous, self.BASE, "Historical release\n")
        replies = {
            ("ls-remote", "--tags", "--refs", "origin", "refs/tags/v*"): result(out=records),
            ("fetch", "--no-tags", "--no-write-fetch-head", "--refmap=", "origin", self.OID): result(),
            ("cat-file", "tag", self.OID): result(out=baseline),
            ("merge-base", "--is-ancestor", self.BASE, SHA): result(),
            ("log", "--no-show-signature", "--no-decorate", "--format=%H%x09%s",
             "--reverse", "--max-count=257", self.BASE + ".." + SHA, "--"): result(out=HISTORY),
        }
        replies.update(overrides or {})
        calls = []

        def git(args, stage, allowed=(0,), **kwargs):
            command = tuple(args)
            calls.append(command)
            self.assertIn(command, replies)
            reply = replies[command]
            tag.require(reply.returncode in allowed, "Synthetic Git failure")
            return reply

        with mock.patch.object(tag, "git", side_effect=git), \
                mock.patch.object(tag, "verify_signature", side_effect=signature_error) as verify:
            text = tag.automatic_notes(self.VERSION, SHA, (POLICY,))
        verify.assert_called_once_with("verify-tag", self.OID, (POLICY,), "release_signers")
        self.assertIn("Changes since [" + previous + "]", text)
        return text, calls

    def test_selects_latest_lower_semver_and_pins_signed_ancestor_object(self):
        records = "\n".join([
            self.OTHER_OID + "\trefs/tags/v0.9.0-rc.9",
            self.OID + "\trefs/tags/v0.9.0-rc.10",
            self.OTHER_OID + "\trefs/tags/v1.0.0",
            self.OTHER_OID + "\trefs/tags/v2.0.0",
            self.OTHER_OID + "\trefs/tags/v-invalid",
        ])
        _, calls = self.generate(records)
        self.assertFalse(any(c[0] == "fetch" and self.OTHER_OID in c for c in calls))
        self.assertTrue(all(c[0] in {"ls-remote", "fetch", "cat-file", "merge-base", "log"} for c in calls))

    def test_skips_a_newer_tag_not_in_target_history(self):
        records = (self.OTHER_OID + "\trefs/tags/v0.9.1\n"
                   + self.OID + "\trefs/tags/v0.9.0-rc.10")
        self.generate(records, {
            ("fetch", "--no-tags", "--no-write-fetch-head", "--refmap=", "origin", self.OTHER_OID): result(),
            ("cat-file", "tag", self.OTHER_OID): result(out=signed_tag("v0.9.1", self.OTHER_BASE, "Other\n")),
            ("merge-base", "--is-ancestor", self.OTHER_BASE, SHA): result(1),
        })

    def test_invalid_or_unsigned_baseline_cannot_silently_select_older_history(self):
        record = self.OID + "\trefs/tags/v0.9.0-rc.10"
        with self.assertRaises(tag.TagError):
            self.generate(record, signature_error=tag.TagError("Unauthorized signer"))
        for raw in ("unsigned tag", signed_tag("v0.9.0-rc.9", self.BASE, "Wrong name\n")):
            with self.assertRaises(tag.TagError):
                self.generate(record, {("cat-file", "tag", self.OID): result(out=raw)})
        for records in (record + "\n" + record, "bad record", "0" * 40 + "\trefs/tags/v0.9.0"):
            with self.assertRaises(tag.TagError):
                self.generate(records)


class MakeTagTests(unittest.TestCase):
    def test_make_passes_literal_values_without_shell_or_make_expansion(self):
        # A disposable Python receiver replaces tag_release.py. No Git/GPG runs.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "tools").mkdir()
            (root / "tools/github_release.py").write_text(
                "import json, os\nprint(json.dumps([os.environ.get('SUPIVPN_TAG_VERSION'), "
                "os.environ.get('SUPIVPN_TAG_COMMIT')]))\n")
            make = shutil.which("make")
            self.assertIsNotNone(make)
            for version, commit in ((VERSION, None), (VERSION, SHA), ("", ""),
                                    ("$(shell touch sentinel)", "`touch sentinel`"),
                                    ("v1.2.3'; touch sentinel; #", '$(touch sentinel)"\n')):
                args = [make, "--no-print-directory", "-f", str(tag.ROOT / "Makefile"),
                        "tag", "VERSION=" + version]
                if commit is not None:
                    args.append("COMMIT=" + commit)
                env = {key: value for key, value in os.environ.items() if key != "COMMIT"}
                run = subprocess.run(args, cwd=root, env=env, capture_output=True, text=True, timeout=15)
                self.assertEqual(run.returncode, 0, run.stderr)
                self.assertEqual(json.loads(run.stdout), [version, "main" if commit is None else commit])
                self.assertFalse((root / "sentinel").exists())


if __name__ == "__main__":
    unittest.main()
