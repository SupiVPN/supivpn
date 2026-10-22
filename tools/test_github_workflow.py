# Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
# Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
# SPDX-License-Identifier: AGPL-3.0-only
import importlib.util
from pathlib import Path
import re
import json
import os
import subprocess
import sys
from unittest.mock import patch
import unittest

import artifacts as a

try:
    import yaml
except ImportError:
    yaml = None

ROOT = Path(__file__).resolve().parents[1]


def module(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "ci" / (name + ".py"))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


class CandidateContextTests(unittest.TestCase):
    def test_only_canonical_tag_push_with_complete_identity_can_package(self):
        candidate = module("github_candidate")
        valid = {"GITHUB_REPOSITORY": "SupiVPN/supivpn", "GITHUB_REF": "refs/tags/v0.4.0",
                 "GITHUB_EVENT_NAME": "push", "GITHUB_SHA": "a" * 40,
                 "GITHUB_RUN_ID": "42", "GITHUB_RUN_ATTEMPT": "1", "ARCH": "arm64"}
        self.assertEqual(candidate.validate_context(valid), ("a" * 40, "v0.4.0"))
        for key, value in (("GITHUB_REPOSITORY", "other/fork"), ("GITHUB_REF", "refs/pull/1/merge"),
                           ("GITHUB_EVENT_NAME", "pull_request"), ("GITHUB_EVENT_NAME", "workflow_dispatch"),
                            ("GITHUB_SHA", "0" * 40), ("GITHUB_RUN_ATTEMPT", ""),
                            ("GITHUB_REF", "refs/heads/main"), ("GITHUB_REF", "refs/tags/v1;echo bad"),
                            ("GITHUB_REF", "refs/tags/v01.0.0")):
            with self.assertRaises(a.ValidationError):
                candidate.validate_context(dict(valid, **{key: value}))

    def test_tag_authentication_rejects_moved_tag_before_producing_build_identity(self):
        candidate = module("github_candidate")
        env = {"GITHUB_REPOSITORY": "SupiVPN/supivpn", "GITHUB_REF": "refs/tags/v0.4.0",
               "GITHUB_EVENT_NAME": "push", "GITHUB_SHA": "a" * 40,
               "GITHUB_RUN_ID": "42", "GITHUB_RUN_ATTEMPT": "1"}
        with patch.dict(os.environ, env, clear=True), \
                patch.object(candidate.github_release, "configure_origin"), \
                patch.object(candidate.github_release, "public_keyring"), \
                patch.object(candidate.github_release.release_identity, "release_identity",
                             return_value=("b" * 40, "c" * 40)), \
                self.assertRaisesRegex(a.ValidationError, "workflow commit"):
            candidate.verify_tag()


@unittest.skipIf(yaml is None, "PyYAML required for workflow checks")
class WorkflowTests(unittest.TestCase):
    def workflow(self, name):
        return yaml.load((ROOT / ".github/workflows" / name).read_text(), Loader=yaml.BaseLoader)

    def test_regular_checks_are_read_only_and_use_both_native_architectures(self):
        config = self.workflow("checks.yml")
        self.assertEqual(config["permissions"], {"contents": "read"})
        self.assertEqual(config["on"]["push"]["branches"], ["main"])
        self.assertEqual(config["on"]["push"]["tags"], ["v*"])
        self.assertNotIn("pull_request_target", config["on"])
        self.assertTrue(any("apt-get install" in step.get("run", "") and "gnupg" in step["run"]
                            for step in config["jobs"]["audit"]["steps"]))
        for name in ("tests", "build", "openvpn", "debian"):
            self.assertEqual({x["runner"] for x in config["jobs"][name]["strategy"]["matrix"]["include"]},
                             {"ubuntu-24.04-arm", "ubuntu-24.04"})
        for name, job in config["jobs"].items():
            self.assertNotIn("environment", job)
            if name != "attest":
                self.assertNotIn("permissions", job)
        service = config["jobs"]["tests"]["services"]["postgres"]
        self.assertEqual(service["ports"], ["127.0.0.1:55432:5432"])

    def test_only_tag_builds_upload_candidates_without_signing_credentials(self):
        jobs = self.workflow("checks.yml")["jobs"]
        authentication = next(step for step in jobs["scope"]["steps"] if step.get("id") == "tag")
        self.assertIn("refs/tags/", authentication["if"])
        self.assertEqual(authentication["run"], "python3 -B ci/github_candidate.py verify-tag")
        self.assertEqual(jobs["build"]["env"]["SUPIVPN_TAG_OID"], "${{ needs.scope.outputs.tag_oid }}")
        for step in jobs["build"]["steps"]:
            if step.get("uses", "").startswith("actions/upload-artifact@"):
                self.assertIn("refs/tags/", step["if"])
                self.assertEqual(step["with"]["name"],
                                 "candidate-${{ github.ref_name }}-${{ matrix.arch }}-${{ github.sha }}")
        self.assertNotIn("secrets.", str(jobs))

    def test_only_canonical_tag_artifacts_can_be_attested(self):
        job = self.workflow("checks.yml")["jobs"]["attest"]
        self.assertEqual(job["if"], "github.event_name == 'push' && startsWith(github.ref, 'refs/tags/')"
                         " && github.repository == 'SupiVPN/supivpn'")
        self.assertEqual(set(job["needs"]), {"scope", "build"})
        self.assertEqual(job["permissions"], {"contents": "read", "id-token": "write", "attestations": "write"})
        self.assertEqual(job["strategy"]["matrix"]["arch"], ["arm64", "amd64"])
        # No checkout, shell, cache restore, cross-run download or private signing key.
        download, attest = job["steps"]
        self.assertEqual(set(download), {"uses", "with"})
        self.assertTrue(download["uses"].startswith("actions/download-artifact@"))
        self.assertEqual(download["with"], {"name": "candidate-${{ github.ref_name }}-${{ matrix.arch }}-${{ github.sha }}",
                                            "path": "candidate"})
        self.assertEqual(set(attest), {"uses", "with"})
        self.assertTrue(attest["uses"].startswith("actions/attest@"))
        self.assertEqual(attest["with"], {"subject-path": "candidate/*.tar.gz", "create-storage-record": "false"})

    def test_independent_checks_run_in_parallel_with_a_complete_final_gate(self):
        jobs = self.workflow("checks.yml")["jobs"]
        executable = {"tests", "security", "fuzz", "build", "openvpn", "debian"}
        self.assertNotIn("needs", jobs["scope"])
        self.assertNotIn("needs", jobs["audit"])
        for name in executable:
            self.assertEqual(jobs[name]["needs"], "scope")
            self.assertEqual(jobs[name]["if"], "needs.scope.outputs.code == 'true'")
        gate = jobs["required"]
        self.assertEqual(set(gate["needs"]), executable | {"scope", "audit", "attest"})
        self.assertEqual(gate["env"]["ATTEST_EXPECTED"], "${{ " + jobs["attest"]["if"] + " }}")
        self.assertEqual(gate["if"], "always()")
        self.assertEqual(gate["name"], "Required checks")
        # Execute the actual gate against success, skips, failures and cancellations.
        command = gate["steps"][0]["run"]
        self.assertTrue(command.startswith("python3 - <<'PY'\n") and command.endswith("PY\n"))
        program = command.split("\n", 1)[1].rsplit("PY\n", 1)[0]
        def passed(results, attest):
            return subprocess.run([sys.executable, "-c", program],
                                  env=dict(os.environ, RESULTS=json.dumps(results), ATTEST_EXPECTED=attest),
                                  capture_output=True, timeout=5).returncode == 0
        for code, attest in (("true", "true"), ("true", "false"), ("false", "false")):
            good = {name: {"result": "success" if code == "true" else "skipped"}
                    for name in executable}
            good.update(scope={"result": "success", "outputs": {"code": code}},
                        audit={"result": "success"},
                        attest={"result": "success" if attest == "true" else "skipped"})
            self.assertTrue(passed(good, attest))
            for name in gate["needs"]:
                for result in ("success", "failure", "cancelled", "skipped"):
                    if result == good[name]["result"]:
                        continue
                    bad = dict(good, **{name: dict(good[name], result=result)})
                    self.assertFalse(passed(bad, attest), (code, attest, name, result))
            for code_value in ("", "unknown", None):
                bad = dict(good, scope={"result": "success", "outputs": {"code": code_value}})
                self.assertFalse(passed(bad, attest))
            self.assertFalse(passed(good, ""))

    def test_only_environment_approved_publication_can_write(self):
        config = self.workflow("release.yml")
        self.assertEqual(set(config["on"]), {"workflow_dispatch"})
        self.assertEqual(config["jobs"]["prepare"]["permissions"],
                         {"contents": "read", "actions": "read", "attestations": "read"})
        publish = config["jobs"]["publish"]
        signer = config["jobs"]["sign"]
        self.assertEqual(signer["environment"], "release")
        self.assertEqual(signer["needs"], "prepare")
        self.assertEqual(signer["permissions"], {"contents": "read"})
        self.assertEqual(publish["needs"], "sign")
        self.assertNotIn("environment", publish)
        self.assertEqual(publish["permissions"], {"contents": "write", "actions": "read"})
        self.assertIn("refs/heads/main", publish["if"])
        for name, job in config["jobs"].items():
            secret_steps = [step for step in job["steps"] if "secrets." in str(step.get("env", {}))]
            self.assertEqual(len(secret_steps), 1 if name == "sign" else 0)
            if secret_steps:
                self.assertNotIn("GH_TOKEN", secret_steps[0].get("env", {}))

    def test_actions_are_pinned_and_checkouts_do_not_retain_tokens(self):
        for name in ("checks.yml", "release.yml"):
            config = self.workflow(name)
            for job in config["jobs"].values():
                self.assertIn("timeout-minutes", job)
                for step in job["steps"]:
                    if "uses" in step:
                        self.assertRegex(step["uses"], r"^[a-zA-Z0-9_./-]+@[a-f0-9]{40}$")
                    if step.get("uses", "").startswith("actions/checkout@"):
                        self.assertEqual(step["with"]["persist-credentials"], "false")
