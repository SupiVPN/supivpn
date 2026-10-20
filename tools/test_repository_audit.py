# Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
# Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
# SPDX-License-Identifier: AGPL-3.0-only
import contextlib
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import repository_audit as audit


class RepositoryAuditTests(unittest.TestCase):
    def test_signer_policy_does_not_allow_arbitrary_ci_json(self):
        self.assertTrue(audit.permitted(Path("ci/signers.json")))
        self.assertFalse(audit.permitted(Path("ci/credentials.json")))
        self.assertFalse(audit.permitted(Path("ci/local/signers.json")))

    def test_detects_sensitive_patterns_without_echoing_values(self):
        samples = [
            ("private-key-material", "-----BEGIN " + "PRIVATE KEY-----"),
            ("cloud-access-key", "AKIA" + "A" * 16),
            ("access-token", "glpat-" + "a" * 24),
            ("credential-in-url", "https://" + "operator:example-password@host.invalid"),
            ("personal-checkout-path", "/Users/" + "example/work/"),
            ("idp-tenant-identifier", "00g" + "example123456789"),
            ("non-example-aws-account", "arn:aws:lambda:region:" + "987654321098:function:example"),
        ]
        for category, value in samples:
            with self.subTest(category=category):
                hits = audit.findings("first line\n" + value)
                self.assertIn((2, category), hits)
                self.assertNotIn(value, repr(hits))

    def test_exact_negative_test_exceptions_do_not_hide_other_values(self):
        path = "internal/agentclient/client_test.go"
        safe = "https://" + "u:p@example.test"
        self.assertEqual(audit.findings(safe, relative=path), [])
        self.assertTrue(audit.findings(safe, relative="internal/agent/runtime.go"))
        self.assertTrue(audit.findings("https://" + "u:changed@example.test", relative=path))

    def test_excluded_material_is_not_read_and_symlinks_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "runtime/local").mkdir(parents=True)
            (root / "internal/agent").mkdir(parents=True)
            (root / "runtime/local/secret.key").write_bytes(b"\0")
            (root / ".codex").mkdir()
            (root / ".codex/private.json").write_bytes(b"\0")
            (root / "internal/agent/runtime.go").write_text("package main\n")
            (root / "internal/agent/config.json").write_text("{}")
            (root / "internal/agent/link.go").symlink_to(root / "runtime/local/secret.key")
            candidates, ignored, issues = audit.audit(root)
            self.assertEqual(candidates, ["internal/agent/runtime.go"])
            self.assertEqual(set(ignored), {".codex", "runtime"})
            self.assertEqual({issue[2] for issue in issues}, {
                "symbolic-link-requires-review", "unexpected-source-file"})

    def test_forbidden_deployment_text_is_case_insensitive_and_not_echoed(self):
        self.assertEqual(audit.findings("Example-Organization", ["example-organization"]),
                         [(1, "forbidden-deployment-text")])

    def test_binary_disguised_as_source_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "README.md").write_bytes(b"\0binary")
            _, _, issues = audit.audit(root)
            self.assertEqual(issues, [("README.md", 0, "binary-or-oversized-source")])

    def test_cli_reports_only_paths_lines_and_categories(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            secret = "glpat-" + "a" * 24
            (root / "README.md").write_text(secret)
            output = io.StringIO()
            with patch.object(audit, "ROOT", root), patch("sys.argv", ["audit"]), contextlib.redirect_stdout(output):
                self.assertTrue(audit.main())
            self.assertIn("access-token", output.getvalue())
            self.assertNotIn(secret, output.getvalue())


if __name__ == "__main__":
    unittest.main()
