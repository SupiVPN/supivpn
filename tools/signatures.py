#!/usr/bin/env python3
# Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
# Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
# SPDX-License-Identifier: AGPL-3.0-only
"""Validate release signer policy and machine-readable OpenPGP status."""
import json
import re

class VerificationError(Exception):
    """A fixed diagnostic safe to show without tool output or variable values."""


def parse_policy(data):
    def unique_object(pairs):
        result = {}
        for name, value in pairs:
            if name in result:
                raise ValueError()
            result[name] = value
        return result

    try:
        if len(data) > 8192:
            raise ValueError()
        policy = json.loads(data, object_pairs_hook=unique_object)
        if not isinstance(policy, dict) or set(policy) != {
                "release_signers", "tag_signing_subkeys", "artifact_signing_subkeys"}:
            raise ValueError()
        for signers in policy.values():
            if (not isinstance(signers, list) or not 1 <= len(signers) <= 32
                    or any(not isinstance(item, str) or not re.fullmatch(r"[A-F0-9]{40}", item)
                           for item in signers) or len(set(signers)) != len(signers)):
                raise ValueError()
        if (set(policy["tag_signing_subkeys"]) & set(policy["artifact_signing_subkeys"])
                or set(policy["release_signers"]) & (
                    set(policy["tag_signing_subkeys"]) | set(policy["artifact_signing_subkeys"]))):
            raise ValueError()
        return policy
    except (OSError, ValueError, TypeError):
        raise VerificationError("signer policy is missing or invalid; review ci/signers.json") from None


def read_policy(path):
    try:
        with path.open("rb") as stream:
            return parse_policy(stream.read(8193))
    except OSError:
        raise VerificationError("signer policy is missing or invalid; review ci/signers.json") from None


def valid_signature(status, allowed, subkeys=None):
    records = [line.split()[1:] for line in status.splitlines() if line.startswith("[GNUPG:] ")]
    rejected = {"BADSIG", "ERRSIG", "EXPSIG", "EXPKEYSIG", "REVKEYSIG", "NO_PUBKEY", "NODATA", "FAILURE"}
    if any(row and row[0] in rejected for row in records):
        return False
    valid = [row for row in records if row and row[0] == "VALIDSIG"]
    if len(valid) != 1 or len(valid[0]) not in {10, 11}:
        return False
    primary = valid[0][10] if len(valid[0]) == 11 else valid[0][1]
    return (primary in allowed and valid[0][8] in {"8", "9", "10", "11"}
            and (subkeys is None or valid[0][1] in subkeys))
