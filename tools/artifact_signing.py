# Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
# Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
# SPDX-License-Identifier: AGPL-3.0-only
"""Sign checksum manifests with a dedicated CI subkey in an ephemeral keyring."""
import os
from pathlib import Path
import subprocess
import tempfile

import artifacts as a
import signatures

KEY_ENV = "SUPIVPN_ARTIFACT_SIGNING_KEY"
PASSPHRASE = "SUPIVPN_ARTIFACT_SIGNING_PASSPHRASE"


def secret_subkey(records, policy):
    """Reject a usable primary, extra private keys, or the tag-signing subkey."""
    keys = []
    for line in records.splitlines():
        row = line.split(":")
        if row[0] in {"sec", "ssb"}:
            a.require(len(row) > 14, "Incomplete signing-key inventory")
            keys.append({"kind": row[0], "available": row[14], "usage": row[11], "fpr": None})
        elif row[0] == "fpr" and keys and keys[-1]["fpr"] is None:
            keys[-1]["fpr"] = row[9]
    primary = [k for k in keys if k["kind"] == "sec"]
    usable = [k for k in keys if k["available"] != "#"]
    a.require(len(primary) == 1 and primary[0]["available"] == "#"
              and primary[0]["fpr"] in policy["release_signers"],
              "CI must contain only a primary-key stub")
    a.require(len(usable) == 1 and usable[0]["kind"] == "ssb" and usable[0]["available"] == "+"
              and usable[0]["usage"] == "s"
              and usable[0]["fpr"] in policy["artifact_signing_subkeys"],
              "CI requires exactly one authorized artifact-signing subkey")
    return usable[0]["fpr"]


def verify(manifest, signature, policy, *, home=None, env=None):
    a.regular(manifest, 8192)
    a.regular(signature, 8192)
    args = ["gpg", "--batch", "--no-auto-key-retrieve"]
    if home is not None:
        args += ["--no-options", "--homedir", str(home)]
    result = subprocess.run(
        [*args, "--status-fd=1", "--verify", str(signature), str(manifest)],
        capture_output=True, text=True, timeout=30, env=env,
    )
    a.require(result.returncode == 0 and signatures.valid_signature(
        result.stdout, policy["release_signers"], policy["artifact_signing_subkeys"]),
        "Artifact signature invalid or unauthorized")


def sign(manifest, policy):
    private = os.environ.pop(KEY_ENV, "")
    passphrase = os.environ.pop(PASSPHRASE, "")
    a.require(0 < len(private) <= 65536 and private.startswith("-----BEGIN PGP PRIVATE KEY BLOCK-----")
              and private.count("-----BEGIN PGP ") == 1, "Configure the CI signing-subkey environment secret")
    a.require(0 < len(passphrase) <= 4096 and not any(c in passphrase for c in "\r\n\0"),
              "Configure the CI signing-passphrase environment secret")
    a.regular(manifest, 8192)
    target = manifest.with_name(manifest.name + ".asc")
    a.require(not target.exists() and not target.is_symlink(), "Artifact signature already exists")
    # Pass armored input and passphrase through pipes, not argv or child environments.
    # GnuPG's imported private subkey lives only in the temporary keyring.
    env = {k: v for k, v in os.environ.items()
           if k not in {KEY_ENV, PASSPHRASE, "GH_TOKEN", "GITHUB_TOKEN", "GNUPGHOME"}}
    with tempfile.TemporaryDirectory(prefix="supivpn-sign-") as directory:
        home = Path(directory).resolve()
        home.chmod(0o700)
        (home / "gpg-agent.conf").write_text("default-cache-ttl 0\nmax-cache-ttl 0\n")
        args = ["gpg", "--no-options", "--homedir", directory, "--batch", "--no-tty",
                "--no-auto-key-retrieve", "--no-auto-key-import"]
        def run(extra, data=None):
            result = subprocess.run([*args, *extra], input=data, capture_output=True, timeout=60, env=env)
            a.require(result.returncode == 0, "Artifact signing failed; inspect secret configuration and expiry")
            return result.stdout
        try:
            run(["--import"], private.encode())
            private = ""
            key = secret_subkey(run(["--with-colons", "--list-secret-keys"]).decode(), policy)
            raw = run(["--pinentry-mode", "loopback", "--passphrase-fd", "0",
                       "--local-user", key + "!", "--digest-algo", "SHA512",
                       "--armor", "--detach-sign", "--output", "-", str(manifest)],
                      (passphrase + "\n").encode())
            passphrase = ""
            a.require(0 < len(raw) <= 8192 and raw.startswith(b"-----BEGIN PGP SIGNATURE-----"),
                      "Invalid artifact signature output")
            check = home / "signature.asc"
            check.write_bytes(raw)
            verify(manifest, check, policy, home=home, env=env)
            with target.open("xb") as stream:
                stream.write(raw)
        finally:
            subprocess.run(["gpgconf", "--homedir", directory, "--kill", "gpg-agent"],
                           capture_output=True, timeout=15, env=env)
    return target
