# Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
# Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
# SPDX-License-Identifier: AGPL-3.0-only
import json
import unittest

import signatures as s

KEY = "A" * 40
SUBKEY = "B" * 40


class SignatureTests(unittest.TestCase):
    def test_accepts_pinned_primary_or_its_signing_subkey(self):
        for signing in (KEY, SUBKEY):
            status = f"[GNUPG:] VALIDSIG {signing} 2026-10-20 1 0 4 0 1 10 00 {KEY}\n"
            self.assertTrue(s.valid_signature(status, [KEY]))
            self.assertEqual(s.valid_signature(status, [KEY], [SUBKEY]), signing == SUBKEY)
            self.assertFalse(s.valid_signature(status, ["C" * 40]))
            self.assertFalse(s.valid_signature(status.replace("1 10 00", "1 2 00"), [KEY]))
            self.assertFalse(s.valid_signature(status + status, [KEY]))
            for marker in ("BADSIG", "ERRSIG", "EXPSIG", "EXPKEYSIG", "REVKEYSIG", "NO_PUBKEY", "NODATA", "FAILURE"):
                self.assertFalse(s.valid_signature(status + "[GNUPG:] " + marker, [KEY]))
        self.assertFalse(s.valid_signature("", [KEY]))

    def test_policy_is_bounded_unique_and_release_only(self):
        policy = {"release_signers": [KEY], "tag_signing_subkeys": [SUBKEY],
                  "artifact_signing_subkeys": ["C" * 40]}
        self.assertEqual(s.parse_policy(json.dumps(policy)), policy)
        for data in ('{}', '[]', '{"release_signers": [], "release_signers": []}',
                     json.dumps(dict(policy, artifact_signing_subkeys=[SUBKEY])),
                     json.dumps(dict(policy, tag_signing_subkeys=[KEY])),
                     json.dumps({"release_signers": [KEY, KEY]}),
                     json.dumps({"release_signers": ["short"]}),
                     json.dumps({"release_signers": [KEY], "unexpected": [KEY]}), " " * 8193):
            with self.assertRaises(s.VerificationError):
                s.parse_policy(data)
