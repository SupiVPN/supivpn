# Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
# Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
# SPDX-License-Identifier: AGPL-3.0-only
"""Prevent faster CI from silently dropping tests selected without integration tags."""
import copy
import contextlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "ci"))
import check_test_coverage as coverage


class CombinedCoverageTests(unittest.TestCase):
    def setUp(self):
        self.ordinary = {"supivpn": {"ImportPath": "supivpn", "GoFiles": ["main.go"],
                                    "TestGoFiles": ["security_test.go"],
                                    "XTestGoFiles": ["external_test.go"],
                                    "EmbedFiles": ["migration.sql"]}}
        self.combined = copy.deepcopy(self.ordinary)
        self.combined["supivpn"]["TestGoFiles"].append("postgres_integration_test.go")

    def test_combined_run_accepts_additional_tests(self):
        coverage.verify(self.ordinary, self.combined)
        coverage.verify(self.ordinary, self.ordinary)

    def test_missing_unit_external_or_embedded_test_input_is_rejected(self):
        for field in coverage.TEST_FIELDS:
            original = copy.deepcopy(self.ordinary)
            original["supivpn"][field] = ["required-test-input"]
            with self.subTest(field=field), self.assertRaises(ValueError):
                coverage.verify(original, self.combined)

    def test_missing_package_or_changed_production_code_is_rejected(self):
        with self.assertRaises(ValueError):
            coverage.verify(self.ordinary, {})
        for field in coverage.SOURCE_FIELDS:
            changed = copy.deepcopy(self.combined)
            changed["supivpn"][field] = ["replacement"]
            with self.subTest(field=field), self.assertRaises(ValueError):
                coverage.verify(self.ordinary, changed)

    def test_parses_go_json_stream_and_rejects_empty_duplicates_and_errors(self):
        first = self.ordinary["supivpn"]
        second = {"ImportPath": "supivpn/internal/saml"}
        stream = json.dumps(first) + "\n" + json.dumps(second)
        self.assertEqual(set(coverage.packages(stream)), {"supivpn", "supivpn/internal/saml"})
        for data in ("", "{}", "{", json.dumps(first) * 2,
                     json.dumps(dict(first, Error={"Err": "synthetic"}))):
            with self.subTest(data=data), self.assertRaises(ValueError):
                coverage.packages(data)

    def test_command_errors_fail_closed_without_raw_diagnostics(self):
        with mock.patch.object(coverage.subprocess, "run", side_effect=OSError("private diagnostic")), \
                self.assertRaises(SystemExit) as stopped:
            coverage.main()
        self.assertNotIn("private diagnostic", str(stopped.exception))

    def test_failure_reports_phase_and_safe_reason_without_tool_output(self):
        cases = [
            (subprocess.CalledProcessError(1, "go", stderr="error obtaining VCS status: private diagnostic"),
             "Go could not inspect VCS metadata"),
            (subprocess.CalledProcessError(2, "go", stderr="private diagnostic"), "exited with code 2"),
            (subprocess.CalledProcessError(2, "go", stderr="-race requires cgo; private diagnostic"), "requires CGO"),
            (subprocess.TimeoutExpired("private diagnostic", 90), "timed out after 90 seconds"),
            (FileNotFoundError("private diagnostic"), "executable or module root is missing"),
        ]
        good = mock.Mock(stdout=json.dumps(self.ordinary["supivpn"]))
        for error, expected in cases:
            for prefix, phase in (([], "ordinary package selection"), ([good], "integration package selection")):
                with self.subTest(reason=expected, phase=phase), \
                        mock.patch.object(coverage.subprocess, "run", side_effect=[*prefix, error]), \
                        self.assertRaises(SystemExit) as stopped:
                    coverage.main()
                message = str(stopped.exception)
                self.assertIn(phase, message)
                self.assertIn(expected, message)
                self.assertNotIn("private diagnostic", message)

    def test_missing_test_reports_comparison_failure(self):
        changed = copy.deepcopy(self.combined)
        changed["supivpn"]["TestGoFiles"] = []
        with mock.patch.object(coverage.subprocess, "run", side_effect=[
                mock.Mock(stdout=json.dumps(value["supivpn"])) for value in (self.ordinary, changed)]), \
                self.assertRaises(SystemExit) as stopped:
            coverage.main()
        self.assertIn("coverage comparison: Integration tags exclude ordinary tests", str(stopped.exception))

    def test_real_entry_point_compares_both_build_modes_before_success(self):
        outputs = [json.dumps(value["supivpn"]) for value in (self.ordinary, self.combined)]
        with mock.patch.object(coverage.subprocess, "run", side_effect=[
                mock.Mock(stdout=value) for value in outputs]) as run, \
                contextlib.redirect_stdout(io.StringIO()):
            coverage.main()
        self.assertEqual(run.call_args_list[0].args[0], ["go", "list", "-buildvcs=false", "-race", "-json", "./..."])
        self.assertEqual(run.call_args_list[1].args[0], ["go", "list", "-buildvcs=false", "-race", "-json", "-tags=integration", "./..."])
        for call in run.call_args_list:
            self.assertTrue(call.kwargs["check"])
            self.assertEqual(call.kwargs["cwd"], coverage.ROOT)

    @unittest.skipUnless(shutil.which("git") and shutil.which("go"), "Git and Go are required")
    def test_real_go_list_in_helper_owned_checkout_needs_no_git_trust_override(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            runtime = root
            (runtime / "go.mod").write_text("module coverage.test\n\ngo 1.20\n")
            (runtime / "main.go").write_text("package main\nfunc main() {}\n")
            (runtime / "main_test.go").write_text(
                'package main\nimport "testing"\nfunc TestOrdinary(t *testing.T) {}\n')
            (runtime / "integration_test.go").write_text(
                '//go:build integration\n\npackage main\nimport "testing"\nfunc TestIntegration(t *testing.T) {}\n')
            env = dict(os.environ, GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL="/dev/null",
                       GIT_TEST_ASSUME_DIFFERENT_OWNER="1", GOPROXY="off", GOSUMDB="off",
                       GOTOOLCHAIN="local", GOWORK="off", GOFLAGS="", GOENV="off",
                       GOCACHE=str(root / "cache"), GOPATH=str(root / "go"))
            subprocess.run(["git", "-c", "init.templateDir=", "init", "--quiet", str(root)],
                           env=env, check=True, capture_output=True, timeout=15)
            unpatched = subprocess.run(["go", "list", "-race", "-json", "./..."],
                                       cwd=runtime, env=env, capture_output=True, text=True, timeout=90)
            self.assertNotEqual(unpatched.returncode, 0)
            self.assertIn("error obtaining VCS status", unpatched.stderr)
            with mock.patch.object(coverage, "ROOT", root), mock.patch.dict(os.environ, env, clear=True), \
                    contextlib.redirect_stdout(io.StringIO()) as output:
                coverage.main()
            self.assertIn("retain all ordinary", output.getvalue())


if __name__ == "__main__":
    unittest.main()
