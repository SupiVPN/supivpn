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
import tempfile
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
    def test_debian_candidates_refuse_untrusted_context_and_extra_build_outputs(self):
        with patch.dict(sys.modules, github_candidate=module("github_candidate")):
            candidate = module("github_debian")
        with patch.dict(os.environ, {"GITHUB_EVENT_NAME": "pull_request"}, clear=True), \
                patch.object(candidate.debian_packages, "build") as build, self.assertRaises(a.ValidationError):
            candidate.main()
        build.assert_not_called()
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            for name in candidate.deb.filenames("v0.6.0", "arm64"):
                (work / name).write_bytes(b"synthetic candidate")
            (work / "openvpn-test.deb").write_bytes(b"must stay local")
            output = work / "output"
            with self.assertRaises(a.ValidationError):
                candidate.retain(work, output, "arm64", "a" * 40, "v0.6.0", "b" * 40,
                                 {"GITHUB_RUN_ID": "42", "GITHUB_RUN_ATTEMPT": "1"})
            self.assertFalse(output.exists())

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

    def test_documentation_scope_has_complete_push_ids_and_light_audit(self):
        jobs = self.workflow("checks.yml")["jobs"]
        step = next(step for step in jobs["scope"]["steps"] if step.get("id") == "scope")
        self.assertEqual(step["env"]["BEFORE_SHA"], "${{ github.event.before }}")
        self.assertEqual(step["env"]["AFTER_SHA"], "${{ github.event.after }}")
        self.assertEqual(step["env"]["PUSH_FORCED"], "${{ toJSON(github.event.forced) }}")
        for name in ("base", "head"):
            self.assertEqual(jobs["scope"]["outputs"][name], "${{ steps.scope.outputs." + name + " }}")
        for step in jobs["audit"]["steps"]:
            if "run" not in step:
                continue
            if "check_docs.py" in step["run"]:
                self.assertEqual(step["if"], "needs.scope.outputs.code == 'false'")
                self.assertNotIn("make audit", step["run"])
                self.assertNotIn("apt-get", step["run"])
                for script in ("repository_audit.py", "check_language.py", "release_notes.py"):
                    self.assertIn(script, step["run"])
            else:
                self.assertEqual(step["if"], "needs.scope.outputs.code == 'true'")

    def test_codeql_retains_languages_queries_and_reports_intentional_skips(self):
        config = self.workflow("codeql.yml")
        self.assertEqual(set(config["on"]), {"push", "pull_request", "schedule", "workflow_dispatch"})
        self.assertEqual(config["on"]["push"], {"branches": ["main"], "tags": ["v*"]})
        self.assertEqual(config["permissions"], {"contents": "read"})
        jobs = config["jobs"]
        step = next(step for step in jobs["scope"]["steps"] if step.get("id") == "scope")
        original = next(step for step in self.workflow("checks.yml")["jobs"]["scope"]["steps"]
                        if step.get("id") == "scope")
        self.assertEqual(step, original)
        analysis = jobs["analyze"]
        self.assertEqual(analysis["needs"], "scope")
        self.assertEqual(analysis["if"], "needs.scope.outputs.code == 'true'")
        self.assertEqual(analysis["permissions"], {"contents": "read", "security-events": "write"})
        languages = analysis["strategy"]["matrix"]["include"]
        self.assertEqual({row["language"] for row in languages},
                         {"actions", "go", "javascript-typescript", "python"})
        for row in languages:
            self.assertEqual(row["build-mode"], "autobuild" if row["language"] == "go" else "none")
        init = next(step for step in analysis["steps"] if "codeql-action/init@" in step.get("uses", ""))
        self.assertEqual(init["with"]["queries"], "security-extended")
        analyze = analysis["steps"][-1]
        self.assertEqual(analyze["with"]["category"], "/language:${{ matrix.language }}")
        self.assertEqual(analyze["with"]["upload-database"], "false")
        self.assertNotIn("secrets.", str(jobs))
        gate = jobs["required"]
        self.assertEqual(gate["needs"], ["scope", "analyze"])
        self.assertEqual(gate["if"], "always()")
        program = gate["steps"][0]["run"].split("\n", 1)[1].rsplit("PY\n", 1)[0]
        for code in ("true", "false", "", None):
            for scope_result in ("success", "failure", "cancelled", "skipped"):
                for result in ("success", "failure", "cancelled", "skipped"):
                    needs = {"scope": {"result": scope_result, "outputs": {"code": code}},
                             "analyze": {"result": result}}
                    actual = subprocess.run([sys.executable, "-c", program],
                                            env=dict(os.environ, RESULTS=json.dumps(needs)),
                                            capture_output=True, timeout=5).returncode == 0
                    expected = scope_result == "success" and (
                        (code == "true" and result == "success") or (code == "false" and result == "skipped"))
                    self.assertEqual(actual, expected, (code, scope_result, result))

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

    def test_real_okta_credentials_are_confined_to_trusted_acceptance(self):
        config = self.workflow("okta.yml")
        self.assertEqual(set(config["on"]), {"schedule", "workflow_dispatch", "push"})
        self.assertEqual(config["on"]["push"]["branches"], ["main"])
        self.assertEqual(config["permissions"], {"contents": "read"})
        job = config["jobs"]["acceptance"]
        for condition in ("github.repository == 'SupiVPN/supivpn'",
                          "github.ref == 'refs/heads/main'",
                          "vars.OKTA_LIVE_TESTS_ENABLED == 'true'"):
            self.assertIn(condition, job["if"])
        self.assertEqual(job["environment"], "okta-tests")
        self.assertNotIn("env", job)
        self.assertNotIn("env", config)
        self.assertEqual(job["services"]["postgres"]["ports"], ["127.0.0.1:55432:5432"])
        credential_steps = [step for step in job["steps"] if "secrets." in str(step)]
        self.assertEqual(len(credential_steps), 1)
        execution = credential_steps[0]
        self.assertEqual(execution["run"], "node ci/okta/run.cjs")
        self.assertEqual({value for value in execution["env"].values() if "secrets." in value},
                         {"${{ secrets.OKTA_TEST_USERNAME }}", "${{ secrets.OKTA_TEST_PASSWORD }}",
                          "${{ secrets.OKTA_ENCRYPTION_PRIVATE_KEY }}"})
        self.assertEqual(execution["env"]["OKTA_ENCRYPTED_METADATA_URL"], "${{ vars.OKTA_ENCRYPTED_METADATA_URL }}")
        self.assertEqual(execution["env"]["OKTA_ENCRYPTION_CERTIFICATE"], "${{ vars.OKTA_ENCRYPTION_CERTIFICATE }}")
        for step in job["steps"]:
            self.assertNotIn("upload-artifact", step.get("uses", ""))
            if step.get("uses", "").startswith("actions/checkout@"):
                self.assertEqual(step["with"]["persist-credentials"], "false")
        self.assertEqual(job["steps"][-1]["if"], "always()")

    def test_only_canonical_tag_artifacts_can_be_attested(self):
        job = self.workflow("checks.yml")["jobs"]["attest"]
        self.assertEqual(job["if"], "github.event_name == 'push' && startsWith(github.ref, 'refs/tags/')"
                         " && github.repository == 'SupiVPN/supivpn'")
        self.assertEqual(set(job["needs"]), {"scope", "build", "debian"})
        self.assertEqual(job["permissions"], {"contents": "read", "id-token": "write", "attestations": "write"})
        self.assertEqual(job["strategy"]["matrix"]["arch"], ["arm64", "amd64"])
        # No checkout, shell, cache restore, cross-run download or private signing key.
        download, attest, deb_download, deb_attest = job["steps"]
        self.assertEqual(set(download), {"uses", "with"})
        self.assertTrue(download["uses"].startswith("actions/download-artifact@"))
        self.assertEqual(download["with"], {"name": "candidate-${{ github.ref_name }}-${{ matrix.arch }}-${{ github.sha }}",
                                            "path": "candidate"})
        self.assertEqual(set(attest), {"uses", "with"})
        self.assertTrue(attest["uses"].startswith("actions/attest@"))
        self.assertEqual(attest["with"], {"subject-path": "candidate/*.tar.gz", "create-storage-record": "false"})
        self.assertEqual(set(deb_download), {"uses", "with"})
        self.assertEqual(deb_download["uses"], download["uses"])
        self.assertEqual(deb_download["with"], {"name": "debian-${{ github.ref_name }}-${{ matrix.arch }}-${{ github.sha }}",
                                                "path": "debian-candidate"})
        self.assertEqual(set(deb_attest), {"uses", "with"})
        self.assertEqual(deb_attest["uses"], attest["uses"])
        self.assertEqual(deb_attest["with"], {"subject-path": "debian-candidate/*.deb\ndebian-candidate/*.dsc\ndebian-candidate/*.tar.xz\n",
                                              "create-storage-record": "false"})
        builder = self.workflow("checks.yml")["jobs"]["debian"]
        self.assertEqual(builder["env"]["SUPIVPN_TAG_OID"], "${{ needs.scope.outputs.tag_oid }}")
        for step in builder["steps"]:
            if step.get("run") == "python3 -B ci/github_debian.py" or "upload-artifact@" in step.get("uses", ""):
                self.assertEqual(step["if"], job["if"])


    def test_independent_checks_run_in_parallel_with_a_complete_final_gate(self):
        jobs = self.workflow("checks.yml")["jobs"]
        executable = {"tests", "security", "fuzz", "build", "openvpn", "debian"}
        self.assertNotIn("needs", jobs["scope"])
        self.assertEqual(jobs["audit"]["needs"], "scope")
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
            self.assertEqual(len(secret_steps), 2 if name == "sign" else 0)
            for step in secret_steps:
                self.assertNotIn("GH_TOKEN", step.get("env", {}))
        self.assertEqual({step["run"] for step in signer["steps"] if "secrets." in str(step.get("env", {}))},
                         {"python3 -B tools/github_release.py sign", "python3 -B tools/apt_repository.py sign"})

    def test_apt_deployment_is_stable_release_only_and_contains_no_signing_keys(self):
        jobs = self.workflow("release.yml")["jobs"]
        checked = jobs["pages-artifact"]
        self.assertEqual(set(checked["needs"]), {"publish", "sign"})
        self.assertEqual(checked["permissions"], {"contents": "read"})
        self.assertEqual(checked["steps"][-1]["with"]["path"], "out/apt/site/")
        pages = jobs["pages"]
        self.assertEqual(pages["needs"], "pages-artifact")
        self.assertEqual(pages["permissions"], {"pages": "write", "id-token": "write"})
        self.assertEqual(pages["environment"]["name"], "github-pages")
        self.assertEqual(len(pages["steps"]), 1)
        self.assertTrue(pages["steps"][0]["uses"].startswith("actions/deploy-pages@"))
        for job in (checked, pages):
            self.assertIn("refs/heads/main", job["if"])
            self.assertIn("!contains(inputs.tag, '-')", job["if"])
            self.assertNotIn("secrets.", str(job))

    def test_actions_are_pinned_and_checkouts_do_not_retain_tokens(self):
        for name in ("checks.yml", "release.yml", "codeql.yml"):
            config = self.workflow(name)
            for job in config["jobs"].values():
                self.assertIn("timeout-minutes", job)
                for step in job["steps"]:
                    if "uses" in step:
                        self.assertRegex(step["uses"], r"^[a-zA-Z0-9_./-]+@[a-f0-9]{40}$")
                    if step.get("uses", "").startswith("actions/checkout@"):
                        self.assertEqual(step["with"]["persist-credentials"], "false")
