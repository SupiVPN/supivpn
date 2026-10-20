# Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
# Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
# SPDX-License-Identifier: AGPL-3.0-only
"""Release tag and source authentication with mocked Git operations."""
import json
import unittest
from unittest.mock import patch

import artifacts as a
import release_identity as d
import tag_release as tag
from test_artifacts import V, C
from test_tag_release import POLICY, result, signed

OID = "b" * 40
MAIN = "c" * 40


class ReleaseIdentityTests(unittest.TestCase):
    def resolve(self, changes=None, version=V):
        ref = "refs/tags/" + V
        replies = {
            ("rev-parse", "--show-toplevel"): result(out=str(tag.ROOT)),
            ("remote", "get-url", "--all", "origin"): result(out=tag.ORIGIN),
            ("ls-remote", "--exit-code", "--refs", "origin", ref, "refs/heads/main"):
                result(out=OID + "\t" + ref + "\n" + MAIN + "\trefs/heads/main\n"),
            ("fetch", "--no-tags", "--no-write-fetch-head", "--refmap=", "origin", OID, MAIN): result(),
            ("cat-file", "-t", OID): result(out="tag"),
            ("verify-tag", "--raw", OID): signed(),
            ("cat-file", "tag", OID): result(out=f"object {C}\ntype commit\ntag {V}\ntagger synthetic\n\nRelease"),
            ("cat-file", "-t", C): result(out="commit"),
            ("show", C + ":ci/signers.json"): result(out=json.dumps(POLICY)),
            ("merge-base", "--is-ancestor", C, MAIN): result(),
        }
        replies.update(changes or {})
        calls = []

        def run(argv, **kwargs):
            command = tuple(argv[9:])
            calls.append(command)
            self.assertIn(command, replies)
            self.assertEqual(kwargs["env"]["GIT_NO_REPLACE_OBJECTS"], "1")
            self.assertFalse(kwargs.get("shell", False))
            return replies[command]

        with patch.object(tag.signatures, "read_policy", return_value=POLICY), \
                patch.object(tag.subprocess, "run", side_effect=run):
            identity = d.release_identity(version)
        self.assertFalse(any(c[0] in {"push", "tag", "checkout", "reset", "update-ref"} for c in calls))
        return identity, calls

    def test_resolves_signed_remote_tag_without_changing_local_refs(self):
        identity, calls = self.resolve()
        self.assertEqual(identity, (C, OID))
        self.assertIn(("fetch", "--no-tags", "--no-write-fetch-head", "--refmap=", "origin", OID, MAIN), calls)

    def test_fails_closed_for_missing_unsigned_foreign_or_moved_tag(self):
        cases = [
            (("remote", "get-url", "--all", "origin"), result(out="git@github.com:other/project.git")),
            (("ls-remote", "--exit-code", "--refs", "origin", "refs/tags/" + V, "refs/heads/main"), result(out="")),
            (("cat-file", "-t", OID), result(out="commit")),
            (("verify-tag", "--raw", OID), signed("D" * 40)),
            (("verify-tag", "--raw", OID), result(1)),
            (("show", C + ":ci/signers.json"), result(out="{}")),
            (("cat-file", "tag", OID), result(out=f"object {C}\ntype commit\ntag v9.9.9\n\nRelease")),
            (("merge-base", "--is-ancestor", C, MAIN), result(1)),
        ]
        for command, response in cases:
            with self.subTest(command=command), self.assertRaises(
                    (a.ValidationError, tag.TagError, tag.signatures.VerificationError)):
                self.resolve({command: response})

    def test_rejects_invalid_version_before_git(self):
        for version in ("", "latest", "../v1.2.3", "v1.2.3;echo oops", "$(touch sentinel)"):
            with patch.object(tag, "git") as git, self.assertRaises(a.ValidationError):
                d.release_identity(version)
            git.assert_not_called()

    def test_root_module_release_reads_only_current_allowlisted_source_paths(self):
        migration = "internal/postgres/migrations/001_initial.sql"
        expected = {a.source_path(name) for name in a.FIXED
                    if name not in a.BUILT_FILES}
        expected.add(migration)
        observed = set()

        def git(command, stage):
            if stage == "release migration list":
                return result(out=migration + "\n")
            self.assertEqual(command[0], "rev-parse")
            self.assertTrue(command[1].startswith(C + ":"))
            observed.add(command[1].split(":", 1)[1])
            return result(out="d" * 40)

        with patch.object(tag, "git", side_effect=git), patch.object(d, "git_blob", return_value=b"source"):
            files = d.release_sources(C)
        self.assertEqual(observed, expected)
        self.assertIn("migrations/001_initial.sql", files)
        self.assertTrue(all(name not in a.BUILT_FILES for name in files))
        with patch.object(tag, "git", return_value=result(out="../unexpected")):
            with self.assertRaises(a.ValidationError):
                d.release_sources(C)
        self.assertNotIn(migration, files)


if __name__ == "__main__":
    unittest.main()
