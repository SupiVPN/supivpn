# Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
# Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
# SPDX-License-Identifier: AGPL-3.0-only
"""Release provenance policy tests; gh and network access are mocked."""
import copy
import json
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

import artifacts as a
import github_release as release

COMMIT = "a" * 40
VERSION = "v1.2.3"
WEB = "https://github.com/SupiVPN/supivpn"
IDENTITY = WEB + "/.github/workflows/checks.yml@refs/tags/" + VERSION
RUN = {"id": 42, "run_attempt": 2}
ARCHIVE = Path("/tmp/synthetic-candidate.tar.gz")


def verified():
    # gh's verified Sigstore certificate JSON has flat extension fields.
    return [{"verificationResult": {"signature": {"certificate": {
        "subjectAlternativeName": IDENTITY,
        "buildConfigURI": IDENTITY,
        "buildConfigDigest": COMMIT,
        "buildTrigger": "push",
        "runInvocationURI": WEB + "/actions/runs/42/attempts/2",
    }}}}]


class ProvenanceTests(unittest.TestCase):
    def verify(self, data, returncode=0):
        reply = subprocess.CompletedProcess([], returncode, json.dumps(data).encode(), b"untrusted diagnostics")
        with patch.object(release.subprocess, "run", return_value=reply) as command:
            release.verify_provenance(ARCHIVE, COMMIT, VERSION, RUN)
        return command.call_args

    def test_verifier_enforces_subject_repository_tag_commit_workflow_and_hosted_runner(self):
        call = self.verify(verified())
        argv = call.args[0]
        self.assertEqual(argv[:4], ["gh", "attestation", "verify", str(ARCHIVE)])
        self.assertIn("--deny-self-hosted-runners", argv)
        flags = argv[4:]
        flags.remove("--deny-self-hosted-runners")
        self.assertEqual(dict(zip(flags[::2], flags[1::2])), {
            "--repo": "SupiVPN/supivpn", "--hostname": "github.com",
            "--cert-identity": IDENTITY,
            "--cert-oidc-issuer": "https://token.actions.githubusercontent.com",
            "--source-digest": COMMIT, "--signer-digest": COMMIT,
            "--source-ref": "refs/tags/" + VERSION,
            "--predicate-type": "https://slsa.dev/provenance/v1", "--format": "json",
        })
        self.assertEqual(call.kwargs, {"capture_output": True, "timeout": 120})

    def test_certificate_must_bind_the_same_tag_workflow_and_run_attempt(self):
        for key, values in {
            "subjectAlternativeName": [IDENTITY.replace("v1.2.3", "v1.2.4"),
                                       IDENTITY.replace("refs/tags/v1.2.3", "refs/heads/main"),
                                       IDENTITY.replace("SupiVPN/supivpn", "other/fork"),
                                       IDENTITY.replace("checks.yml", "release.yml")],
            "buildConfigURI": [IDENTITY.replace("checks.yml", "other.yml")],
            "buildConfigDigest": ["b" * 40],
            "buildTrigger": ["pull_request", "workflow_dispatch"],
            "runInvocationURI": [WEB + "/actions/runs/43/attempts/2",
                                 WEB + "/actions/runs/42/attempts/1",
                                 WEB + "/actions/runs/42/attempts/20",
                                 WEB + "/actions/runs/42"],
        }.items():
            for value in [None, ""] + values:
                with self.subTest(key=key, value=value):
                    data = verified()
                    data[0]["verificationResult"]["signature"]["certificate"][key] = value
                    with self.assertRaisesRegex(a.ValidationError, "selected tag run"):
                        self.verify(data)

    def test_claimed_predicate_cannot_replace_certificate_evidence(self):
        data = verified()
        result = data[0]["verificationResult"]
        result["statement"] = {"predicate": copy.deepcopy(result["signature"]["certificate"])}
        result["signature"]["certificate"]["runInvocationURI"] = WEB + "/actions/runs/999/attempts/1"
        with self.assertRaises(a.ValidationError):
            self.verify(data)

    def test_one_complete_certificate_is_required_without_mixing_claims(self):
        left, right = verified(), verified()
        left[0]["verificationResult"]["signature"]["certificate"]["buildTrigger"] = "workflow_dispatch"
        right[0]["verificationResult"]["signature"]["certificate"]["runInvocationURI"] = "other"
        with self.assertRaises(a.ValidationError):
            self.verify(left + right)
        self.verify(left + verified())

    def test_crypto_failure_is_fatal_even_with_plausible_json(self):
        with self.assertRaisesRegex(a.ValidationError, "^Build provenance verification failed$"):
            self.verify(verified(), returncode=1)

    def test_empty_malformed_or_unverified_results_fail_closed(self):
        for data in (None, {}, [], [None], ["text"], [{}],
                     [{"verificationResult": None}],
                     [{"verificationResult": {"signature": {"certificate": []}}}],
                     [{"attestation": verified()[0]["verificationResult"]}]):
            with self.subTest(data=data), self.assertRaises(a.ValidationError):
                self.verify(data)
        for raw in (b"not json", b"\xff"):
            reply = subprocess.CompletedProcess([], 0, raw, b"untrusted diagnostics")
            with patch.object(release.subprocess, "run", return_value=reply), self.assertRaises(a.ValidationError):
                release.verify_provenance(ARCHIVE, COMMIT, VERSION, RUN)

    def test_missing_cli_or_network_timeout_fails_without_leaking_output(self):
        for error in (FileNotFoundError("untrusted diagnostics"),
                      subprocess.TimeoutExpired("gh", 120, output=b"untrusted diagnostics")):
            with patch.object(release.subprocess, "run", side_effect=error), \
                    self.assertRaisesRegex(a.ValidationError, "^Build provenance verification unavailable or timed out$"):
                release.verify_provenance(ARCHIVE, COMMIT, VERSION, RUN)
