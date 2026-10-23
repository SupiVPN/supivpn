#!/usr/bin/env python3
# Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
# SPDX-License-Identifier: AGPL-3.0-only
"""Build local Debian packages from audited source in an isolated builder."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

import repository_audit
import debian_release


def run(args, **kwargs):
    subprocess.run(args, check=True, **kwargs)


def prepare(root, work, go, *, version=None, epoch=None):
    candidates, _, issues = repository_audit.audit(root)
    if issues:
        raise ValueError("Source audit failed; run make audit before packaging")
    source = work / "source"
    source.mkdir()
    digests = {}
    for name in candidates:
        src, dst = root / name, source / name
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(src, dst, follow_symlinks=False)
        dst.chmod(0o755 if name == "debian/rules" or src.stat().st_mode & 0o111 else 0o644)
        digests[name] = hashlib.sha256(dst.read_bytes()).hexdigest()
    env = dict(os.environ, GOPATH=str(root / "local/go"), GOCACHE=str(root / "local/build-cache"),
               GOTOOLCHAIN="local", GOWORK="off")
    run([go, "mod", "verify"], cwd=root, env=env)
    run([go, "mod", "vendor", "-o", str(source / "vendor")], cwd=root, env=env)
    if version is not None:
        changelog = source / "debian/changelog"
        changelog.write_bytes(debian_release.changelog(changelog.read_bytes(), version, epoch))
        # Shared source and Architecture: all outputs must match across runners.
        for path in sorted(source.rglob("*"), reverse=True) + [source]:
            if path.is_symlink():
                raise ValueError("Source symlinks are not allowed")
            os.utime(path, (epoch, epoch))
    (work / "input-sha256.json").write_text(json.dumps(digests, sort_keys=True, indent=2) + "\n")
    return source


def build(root, arch, go, docker, *, test=False, vm=False, vm_database="local", version=None, epoch=None):
    output = root / "local/debian" / arch
    output.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix="build-", dir=output))
    prepare(root, work, go, version=version, epoch=epoch)
    image = "supivpn-debian-test:trixie-" + arch
    run([docker, "build", "--platform", "linux/" + arch,
         "-t", image, str(root / "ci/debian")])
    run([docker, "run", "--rm", "--platform", "linux/" + arch,
         "--network", "none", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
         "--user", f"{os.getuid()}:{os.getgid()}",
         "--mount", f"type=bind,source={work},target=/work", "--workdir", "/work/source",
         image, "dpkg-buildpackage", "--no-sign", "-F"])
    if test or vm:
        run([docker, "run", "--rm", "--platform", "linux/" + arch,
             "--network", "none", "--security-opt", "no-new-privileges",
             "--mount", f"type=bind,source={work},target=/packages,readonly",
             image, "python3", "/packages/source/ci/debian/check_packages.py", "/packages"])
    if vm:
        from debian_vm import run_vm
        run_vm(root, work, arch, docker, go, database=vm_database)
    print("Debian build and matching source: " + str(work))
    return work


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--arch", choices=["amd64", "arm64"], required=True)
    parser.add_argument("--go", default="go")
    parser.add_argument("--docker", default="docker")
    parser.add_argument("--test", action="store_true")
    parser.add_argument("--vm", action="store_true")
    parser.add_argument("--vm-database", choices=["local", "remote"], default="local")
    parser.add_argument("--version", help="Local release-format build; does not sign or publish")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    epoch = debian_release.commit_epoch(root, "HEAD") if args.version else None
    build(root, args.arch, args.go, args.docker, test=args.test, vm=args.vm, vm_database=args.vm_database,
          version=args.version, epoch=epoch)


if __name__ == "__main__":
    main()
