# Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
# Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
# SPDX-License-Identifier: AGPL-3.0-only
"""GitHub releases: signed tags, verified tag builds and publication."""
from contextlib import contextmanager
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tarfile
import tempfile
import zipfile

import artifacts as a
import artifact_signing
import debian_release as deb
import release_identity
import github_api as gh
import release_notes
import source_archive
import tag_release as tag

ROOT = Path(__file__).resolve().parents[1]


def configure_origin():
    urls = tag.git(["remote", "get-url", "--all", "origin"], "GitHub origin check").stdout.splitlines()
    a.require(len(urls) == 1 and urls[0] in tag.GITHUB_ORIGINS, "Canonical SupiVPN GitHub origin required")
    tag.ORIGIN = urls[0]
    release_notes.WEB = "https://github.com/" + gh.REPOSITORY


def workflow_context(env):
    a.require(env.get("GITHUB_REPOSITORY") == gh.REPOSITORY
              and env.get("GITHUB_EVENT_NAME") == "workflow_dispatch"
              and env.get("GITHUB_REF") == "refs/heads/main", "Release requires canonical main workflow dispatch")
    version = env.get("SUPIVPN_TAG_VERSION", "")
    a.require(len(version) <= 64 and tag.VERSION.fullmatch(version), "Invalid release version")
    return version


@contextmanager
def public_keyring():
    public = os.environ.get("SUPIVPN_GPG_PUBLIC_KEY", "").encode()
    a.require(0 < len(public) <= 65536 and public.startswith(b"-----BEGIN PGP PUBLIC KEY BLOCK-----")
              and public.count(b"-----BEGIN PGP ") == 1 and b"PRIVATE KEY" not in public,
              "Configure the reviewed armored public key as SUPIVPN_GPG_PUBLIC_KEY")
    previous = {name: os.environ.get(name) for name in ("GNUPGHOME", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_NOSYSTEM")}
    with tempfile.TemporaryDirectory() as directory:
        Path(directory, "gpg.conf").write_text("no-auto-key-retrieve\nno-auto-key-import\n")
        try:
            os.environ.update(GNUPGHOME=directory, GIT_CONFIG_GLOBAL="/dev/null", GIT_CONFIG_NOSYSTEM="1")
            result = subprocess.run(["gpg", "--batch", "--import"], input=public, capture_output=True, timeout=30)
            a.require(result.returncode == 0, "Release public-key import failed")
            yield
        finally:
            for name, value in previous.items():
                if value is None:
                    os.environ.pop(name, None)
                else:
                    os.environ[name] = value


def valid_run(run, commit, version):
    return (isinstance(run, dict) and type(run.get("id")) is int and run["id"] > 0
            and type(run.get("run_attempt")) is int and run["run_attempt"] > 0
            and run.get("path") == ".github/workflows/checks.yml"
            and run.get("head_sha") == commit and run.get("head_branch") == version
            and run.get("event") == "push" and run.get("status") == "completed"
            and run.get("conclusion") == "success"
            and run.get("repository", {}).get("full_name") == gh.REPOSITORY
            and run.get("head_repository", {}).get("full_name") == gh.REPOSITORY)


def select_run(commit, version):
    response = gh.api("actions/workflows/checks.yml/runs?event=push&status=success&head_sha="
                      + commit + "&per_page=100")
    runs = [run for run in response.get("workflow_runs", []) if valid_run(run, commit, version)]
    a.require(runs, "No successful Checks tag push for this exact version and commit")
    return max(runs, key=lambda run: run["id"])


def candidate_zip(data, arch, commit, version, oid, run):
    filename = a.filename(version, arch)
    source = "supivpn-source-" + commit + ".tar.gz"
    expected = {filename, "candidate.json", "SHA256SUMS"}
    if arch == "arm64":
        expected.add(source)
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        entries = archive.infolist()
        a.require(len(entries) == len(expected) and {entry.filename for entry in entries} == expected,
                  "Unexpected candidate artifact files")
        a.require(sum(entry.file_size for entry in entries) <= 2 * a.MAX_BUNDLE, "Candidate artifact too large")
        files = {}
        for entry in entries:
            a.require(not entry.flag_bits & 1 and 0 <= entry.file_size <= a.MAX_BUNDLE
                      and stat.S_IFMT(entry.external_attr >> 16) in {0, stat.S_IFREG}, "Unsafe candidate ZIP member")
            if entry.filename in {"candidate.json", "SHA256SUMS"}:
                a.require(entry.file_size <= 4096, "Candidate metadata too large")
            files[entry.filename] = archive.read(entry)
    record = a.json_object(files["candidate.json"])
    identity = {"format": 2, "repository": gh.REPOSITORY, "commit": commit, "arch": arch,
                "version": version, "tag": oid,
                "run_id": run["id"], "run_attempt": run["run_attempt"], "filename": filename,
                "sha256": a.sha(files[filename])}
    if arch == "arm64":
        identity["source"] = {"filename": source, "sha256": a.sha(files[source])}
    a.require(record == identity, "Candidate provenance mismatch")
    a.require(files["SHA256SUMS"] == a.checksums({filename: record["sha256"]}),
              "Candidate checksum record mismatch")
    return files, record


def fetch_candidate(run, commit, version, oid, arch, *, debian=False):
    records = gh.api("actions/runs/" + str(run["id"]) + "/artifacts?per_page=100")
    matches = [item for item in records.get("artifacts", [])
               if item.get("name") == ("debian-" if debian else "candidate-") + version + "-" + arch + "-" + commit]
    a.require(len(matches) == 1, "Missing or ambiguous tag candidate artifact")
    item = matches[0]
    a.require(item.get("expired") is False and type(item.get("id")) is int and item["id"] > 0
              and type(item.get("size_in_bytes")) is int and 0 < item["size_in_bytes"] <= 2 * a.MAX_BUNDLE
              and item.get("workflow_run", {}).get("id") == run["id"]
              and item.get("workflow_run", {}).get("head_sha") == commit
              and item.get("workflow_run", {}).get("head_branch") == version, "Tag artifact unavailable or mismatched")
    digest = item.get("digest", "")
    a.require(isinstance(digest, str) and digest.startswith("sha256:") and a.HEX.fullmatch(digest[7:]),
              "Tag artifact digest missing")
    status, data = gh.request(gh.API + "actions/artifacts/" + str(item["id"]) + "/zip", limit=2 * a.MAX_BUNDLE)
    a.require(status == 200 and len(data) == item["size_in_bytes"] and a.sha(data) == digest[7:],
              "Tag artifact digest/size mismatch")
    parser = debian_zip if debian else candidate_zip
    return parser(data, arch, commit, version, oid, run)


def debian_zip(data, arch, commit, version, oid, run):
    names = deb.filenames(version, arch)
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        entries = archive.infolist()
        a.require(len(entries) == len(names) + 1
                  and {e.filename for e in entries} == names | {"candidate.json"},
                  "Unexpected Debian candidate files")
        a.require(sum(e.file_size for e in entries) <= 2 * a.MAX_BUNDLE, "Debian candidate too large")
        files = {}
        for entry in entries:
            a.require(not entry.flag_bits & 1 and 0 <= entry.file_size <= a.MAX_BUNDLE
                      and stat.S_IFMT(entry.external_attr >> 16) in {0, stat.S_IFREG},
                      "Unsafe Debian ZIP member")
            a.require(entry.filename != "candidate.json" or entry.file_size <= 4096,
                      "Debian candidate metadata too large")
            files[entry.filename] = archive.read(entry)
    record = a.json_object(files.pop("candidate.json"))
    expected = {"format": 1, "repository": gh.REPOSITORY, "commit": commit, "version": version,
                "tag": oid, "arch": arch, "run_id": run["id"], "run_attempt": run["run_attempt"],
                "assets": {name: a.sha(raw) for name, raw in files.items()}}
    a.require(record == expected, "Debian candidate provenance mismatch")
    return files, record


def verify_provenance(path, commit, version, run):
    """Verify archive bytes with Sigstore, then bind the certificate to this run."""
    web = "https://github.com/" + gh.REPOSITORY
    ref = "refs/tags/" + version
    identity = web + "/.github/workflows/checks.yml@" + ref
    command = ["gh", "attestation", "verify", str(path), "--repo", gh.REPOSITORY,
               "--hostname", "github.com", "--cert-identity", identity,
               "--cert-oidc-issuer", "https://token.actions.githubusercontent.com",
               "--source-digest", commit, "--signer-digest", commit, "--source-ref", ref,
               "--deny-self-hosted-runners", "--predicate-type", "https://slsa.dev/provenance/v1",
               "--format", "json"]
    try:
        result = subprocess.run(command, capture_output=True, timeout=120)
    except (OSError, subprocess.TimeoutExpired):
        raise a.ValidationError("Build provenance verification unavailable or timed out") from None
    # Never echo CLI diagnostics: they can contain credentials or untrusted claims.
    a.require(result.returncode == 0, "Build provenance verification failed")
    try:
        verified = json.loads(result.stdout)
    except (ValueError, UnicodeError):
        raise a.ValidationError("Invalid build provenance verification result") from None
    a.require(isinstance(verified, list) and verified, "Missing verified build provenance")
    expected = {"subjectAlternativeName": identity, "buildConfigURI": identity,
                "buildConfigDigest": commit, "buildTrigger": "push",
                "runInvocationURI": web + "/actions/runs/" + str(run["id"])
                + "/attempts/" + str(run["run_attempt"])}
    for entry in verified:
        try:
            certificate = entry["verificationResult"]["signature"]["certificate"]
        except (KeyError, TypeError):
            continue
        # These fields come from GitHub OIDC, not the workflow-controlled predicate.
        if isinstance(certificate, dict) and all(certificate.get(k) == v for k, v in expected.items()):
            return
    raise a.ValidationError("Build provenance does not match the selected tag run and attempt")


def prepare(version, output):
    commit, oid = release_identity.release_identity(version)
    run = select_run(commit, version)
    sources = release_identity.release_sources(commit)
    expected_source = source_archive.source_files(ROOT, commit, require_checkout=False)
    a.require(not output.exists(), "Release output already exists; refusing replacement")
    output.mkdir(parents=True)
    assets = {}
    compatibility = None
    epoch = deb.commit_epoch(ROOT, commit)
    (ROOT / "local").mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(dir=ROOT / "local") as directory:
        for arch in a.ARCHITECTURES:
            files, record = fetch_candidate(run, commit, version, oid, arch)
            names = [record["filename"]]
            if arch == "arm64":
                names.append(record["source"]["filename"])
            for name in names:
                archive = Path(directory) / name
                archive.write_bytes(files[name])
                verify_provenance(archive, commit, version, run)
            candidate = a.unpack(files[record["filename"]], record["sha256"], version,
                                 commit, Path(directory) / ("cache-" + arch), expected_sources=sources, arch=arch)
            manifest = a.json_object(a.regular(candidate / "release.json", 65536))
            schema = {key: value for key, value in manifest.items() if key != "artifacts"}
            a.require(compatibility is None or compatibility == schema, "Cross-architecture schema mismatch")
            compatibility = schema
            # Publish the exact validated tag-build archive, without rebuilding or repackaging.
            name = record["filename"]
            (output / name).write_bytes(files[name])
            assets[name] = record["sha256"]
            if arch == "arm64":
                source = record["source"]
                source_archive.verify(files[source["filename"]], source["sha256"], commit, expected_source)
                (output / source["filename"]).write_bytes(files[source["filename"]])
                assets[source["filename"]] = source["sha256"]
        for arch in a.ARCHITECTURES:
            files, record = fetch_candidate(run, commit, version, oid, arch, debian=True)
            for name, raw in files.items():
                path = Path(directory) / name
                path.write_bytes(raw)
                verify_provenance(path, commit, version, run)
                if name.endswith(".deb"):
                    deb.verify_package(path, version, arch)
                # Shared source and the all-architecture metapackage must be identical.
                a.require(name not in assets or assets[name] == record["assets"][name],
                          "Cross-architecture Debian asset mismatch")
            deb.verify_source(files[f"supivpn_{deb.version(version)}.tar.xz"],
                              files[f"supivpn_{deb.version(version)}.dsc"], version, expected_source, epoch)
            for name, raw in files.items():
                (output / name).write_bytes(raw)
                assets[name] = record["assets"][name]
    raw = tag.git(["cat-file", "tag", oid], "signed release notes").stdout
    _, notes = release_notes.tag_message(raw, version, commit)
    notes = release_notes.validate(version, notes, allow_commit_subjects=True)
    notes += "\n## Packages\n\nCommit: `" + commit + "`. License: AGPL-3.0-only.\n\n"
    notes += "Verified native ARM64 and AMD64 builds from [Checks](https://github.com/" + gh.REPOSITORY
    notes += "/actions/runs/" + str(run["id"]) + ") for this signed tag. Both bundles use format 3.\n\n"
    notes += "Debian 13 packages for ARM64 and AMD64, a shared metapackage and native Debian source are included. "
    notes += "Install verified matching packages with `apt install ./supivpn*.deb`; see DEPLOYMENT.md.\n\n"
    notes += "GitHub build provenance was verified for all binary archives, Debian assets and Corresponding Source, "
    notes += "including the tag commit and Checks run attempt " + str(run["run_attempt"]) + ".\n\n"
    notes += "Database schema: " + str(compatibility["schema"]) + "; compatible VM schemas: "
    notes += ", ".join(sorted(compatibility["compatible_schemas"], key=int)) + ".\n"
    notes += "Isolated Lambda required schema: " + str(compatibility["schema"]) + ".\n\n"
    notes += "Corresponding Source accompanies the binaries. Verify SHA256SUMS.asc with the pinned "
    notes += "SupiVPN release key, then verify the downloaded files against SHA256SUMS before use.\n"
    (output / "release-notes.md").write_text(notes, encoding="utf-8")
    assets["release-notes.md"] = a.sha(notes.encode())
    sums = a.checksums(assets)
    (output / "SHA256SUMS").write_bytes(sums)
    assets["SHA256SUMS"] = a.sha(sums)
    metadata = {"format": 2, "repository": gh.REPOSITORY, "version": version, "commit": commit,
                "tag": oid, "run_id": run["id"], "run_attempt": run["run_attempt"], "assets": assets}
    (output / "release-metadata.json").write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n")
    print("Prepared verified release " + version + " at " + commit)


def checked_release(directory, version, *, signed=False):
    metadata = a.json_object(a.regular(directory / "release-metadata.json", 8192))
    a.require(metadata.get("format") == 2 and metadata.get("repository") == gh.REPOSITORY
              and metadata.get("version") == version and tag.COMMIT.fullmatch(metadata.get("commit", ""))
              and tag.COMMIT.fullmatch(metadata.get("tag", "")), "Release metadata mismatch")
    expected = {a.filename(version, arch) for arch in a.ARCHITECTURES}
    for arch in a.ARCHITECTURES:
        expected.update(deb.filenames(version, arch))
    expected.update({"supivpn-source-" + metadata["commit"] + ".tar.gz", "SHA256SUMS", "release-notes.md"})
    a.require(set(metadata.get("assets", {})) == expected
              and {path.name for path in directory.iterdir()} == expected | {"release-metadata.json"}
              | ({"SHA256SUMS.asc"} if signed else set()),
              "Unexpected release file set")
    for name, digest in metadata["assets"].items():
        a.require(a.HEX.fullmatch(digest) and a.sha(a.regular(directory / name, a.MAX_BUNDLE)) == digest,
                  "Prepared release changed")
    sums = a.checksums({name: digest for name, digest in metadata["assets"].items() if name != "SHA256SUMS"})
    a.require(a.regular(directory / "SHA256SUMS", 8192) == sums, "Checksum manifest does not cover all release assets")
    if signed:
        policy = tag.signatures.read_policy(ROOT / "ci/signers.json")
        artifact_signing.verify(directory / "SHA256SUMS", directory / "SHA256SUMS.asc", policy)
        metadata["assets"]["SHA256SUMS.asc"] = a.sha(a.regular(directory / "SHA256SUMS.asc", 8192))
    return metadata


def publish(version, directory):
    metadata = checked_release(directory, version, signed=True)
    current = gh.api("git/ref/tags/" + version)
    a.require(current.get("object", {}).get("type") == "tag"
              and current["object"].get("sha") == metadata["tag"], "Remote tag changed")
    run = gh.api("actions/runs/" + str(metadata["run_id"]))
    a.require(valid_run(run, metadata["commit"], version) and run["run_attempt"] == metadata["run_attempt"],
              "Tag candidate run changed or is no longer successful")
    notes = a.regular(directory / "release-notes.md", 65536).decode()
    expected = {"tag_name": version, "name": "SupiVPN " + version,
                "body": notes, "prerelease": "-" in version}
    release = gh.api("releases/tags/" + version, missing=True)
    if release is None:
        drafts = [item for item in gh.api("releases?per_page=100") if item.get("tag_name") == version]
        a.require(len(drafts) <= 1, "Ambiguous existing release")
        release = drafts[0] if drafts else None
    if release is None:
        release = gh.api("releases", method="POST", data={**expected, "draft": True,
                         "target_commitish": metadata["commit"]})
    a.require(all(release.get(key) == value for key, value in expected.items())
              and type(release.get("id")) is int and release["id"] > 0, "Conflicting release exists")
    records = release.get("assets", [])
    assets = {asset.get("name"): asset for asset in records}
    a.require(len(assets) == len(records) and assets.keys() <= metadata["assets"].keys(), "Unexpected published assets")
    for name, digest in metadata["assets"].items():
        existing = assets.get(name)
        raw = a.regular(directory / name, a.MAX_BUNDLE)
        if existing is None:
            a.require(release.get("draft") is True, "Published release is incomplete; never replace it")
            url = "https://uploads.github.com/repos/" + gh.REPOSITORY + "/releases/" + str(release["id"]) + "/assets?name=" + name
            status, reply = gh.request(url, method="POST", data=raw)
            a.require(status == 201, "Release asset upload failed")
            existing = a.json_object(reply)
        a.require(existing.get("name") == name and existing.get("state") == "uploaded"
                  and existing.get("size") == len(raw) and existing.get("digest") == "sha256:" + digest,
                  "Published release bytes conflict")
    if release.get("draft") is True:
        gh.api("releases/" + str(release["id"]), method="PATCH", data={"draft": False, "make_latest": "legacy"})
    confirmed = gh.api("releases/" + str(release["id"]))
    a.require(confirmed.get("draft") is False
              and all(confirmed.get(key) == value for key, value in expected.items()),
              "Release publication unconfirmed")
    confirmed_assets = confirmed.get("assets", [])
    a.require(len(confirmed_assets) == len(metadata["assets"])
              and {item.get("name"): item.get("digest") for item in confirmed_assets}
              == {name: "sha256:" + digest for name, digest in metadata["assets"].items()},
              "Published asset set changed")
    print("https://github.com/" + gh.REPOSITORY + "/releases/tag/" + version)


def main():
    try:
        mode = sys.argv[1:]
        if mode == ["tag"]:
            configure_origin()
            return tag.main()
        if mode in (["prepare"], ["sign"], ["publish"]):
            version = workflow_context(os.environ)
            if mode == ["prepare"]:
                configure_origin()
                with public_keyring():
                    prepare(version, ROOT / "out/github-release")
            elif mode == ["sign"]:
                directory = ROOT / "out/github-release"
                checked_release(directory, version)
                artifact_signing.sign(directory / "SHA256SUMS", tag.signatures.read_policy(ROOT / "ci/signers.json"))
                print("Release checksum manifest signed and verified")
            else:
                a.require(os.environ.get("SUPIVPN_RELEASE_PUBLISH") == "1", "Release publication not enabled")
                with public_keyring():
                    publish(version, ROOT / "out/github-release")
        else:
            raise a.ValidationError("Expected tag, prepare, sign or publish")
    except (a.ValidationError, tag.TagError, tag.signatures.VerificationError) as error:
        print("GitHub release operation refused: " + str(error), file=sys.stderr)
        return 1
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError,
            tarfile.TarError, zipfile.BadZipFile):
        print("GitHub release operation refused; check identity, successful tag artifacts and integrity. No fallback.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
