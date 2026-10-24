#!/usr/bin/env python3
# Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
# SPDX-License-Identifier: AGPL-3.0-only
"""Run installed Debian packages with a real guest kernel and systemd PID 1."""
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile
import time
import uuid

IMAGE_VERSION = "20261021-2638"
# From the official Debian cloud image SHA512SUMS, over authenticated HTTPS.
IMAGE_SHA512 = {
    "arm64": "0720988fd560dfa1d2975c4a1e4c39e3903ffd0f68e75be9e171f889cdbb53b7763dc9c54e951afc34055c6110b3b415196778e468a50bf26d294730a7f8eabe",
    "amd64": "70ef6adc1c16155f8d575731b37d0f976d1c60b6144ac3f57914a3f4b30b202b69584d5d143aa39da0f0fe81df9e5b698909c0d94c7d91c6f6c4bb6581ead5f0",
}


def digest(path, algorithm="sha512"):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, algorithm).hexdigest()


def run(args, **kwargs):
    return subprocess.run(args, check=True, timeout=900, **kwargs)


def image(cache, arch):
    name = f"debian-13-generic-{arch}-{IMAGE_VERSION}.qcow2"
    target = cache / name
    if not target.exists():
        partial = cache / (name + "." + uuid.uuid4().hex + ".partial")
        url = f"https://cloud.debian.org/images/cloud/trixie/{IMAGE_VERSION}/{name}"
        run(["curl", "--fail", "--show-error", "--silent", "--location", "--proto", "=https",
             "--proto-redir", "=https", url, "--output", str(partial)])
        if digest(partial) != IMAGE_SHA512[arch]:
            raise ValueError("Debian image checksum mismatch")
        partial.replace(target)
    if target.is_symlink() or digest(target) != IMAGE_SHA512[arch]:
        raise ValueError("Cached Debian image checksum mismatch")
    return target


def seed(work):
    for name in ("client", "host"):
        run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "disposable-supivpn-vm",
             "-f", str(work / name)])
    config = {
        "hostname": "supivpn-disposable-vm", "disable_root": False, "ssh_pwauth": False,
        "users": [{"name": "root", "lock_passwd": True,
                   "ssh_authorized_keys": [(work / "client.pub").read_text().strip()]}],
        "ssh_keys": {"ed25519_private": (work / "host").read_text(),
                     "ed25519_public": (work / "host.pub").read_text()},
        "write_files": [{"path": "/etc/supivpn-disposable-vm", "permissions": "0600",
                         "content": "Debian package acceptance only\n"}],
    }
    (work / "user-data").write_text("#cloud-config\n" + json.dumps(config))
    (work / "user-data").chmod(0o600)
    (work / "meta-data").write_text("instance-id: supivpn-" + uuid.uuid4().hex + "\n")


def external_database(source, work, docker, vm_container, host_arch):
    """Share only the VM runner's network; PostgreSQL stays outside the guest."""
    fixtures = work / "database"
    fixtures.mkdir(mode=0o700)
    shutil.copyfile(source / "ci/debian/vm/database.py", fixtures / "database.py")
    for filename in ("runtime.password", "migration.password"):
        path = fixtures / filename
        # Exercise libpq quoting and the real systemd EnvironmentFile parser.
        path.write_text(os.urandom(24).hex() + " ' \\ \" $")
        path.chmod(0o600)
    image = "supivpn-setup-db-test:" + host_arch
    run([docker, "build", "--platform", "linux/" + host_arch, "-t", image,
         str(source / "ci/debian/remote-database")])
    container = run([docker, "run", "--rm", "--pull", "never", "--detach",
                     "--platform", "linux/" + host_arch,
                     "--label", "supivpn.disposable-test=true",
                     "--security-opt", "no-new-privileges",
                     "--network", "container:" + vm_container,
                     "--env", "SUPIVPN_VM_DATABASE_TEST=1",
                     "--mount", f"type=bind,source={fixtures},target=/fixture",
                     "--entrypoint", "python3", image, "-B", "/fixture/database.py"],
                    capture_output=True, text=True).stdout.strip()
    try:
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            if (fixtures / "ready").exists():
                return container, fixtures
            time.sleep(1)
        raise TimeoutError("External disposable PostgreSQL did not become ready")
    except BaseException:
        run([docker, "stop", "--time", "10", container], stdout=subprocess.DEVNULL)
        raise


def run_vm(root, packages, arch, docker, go, *, database="local"):
    if database not in {"local", "remote"}:
        raise ValueError("Unknown VM database mode")
    host_arch = {"arm64": "arm64", "aarch64": "arm64", "x86_64": "amd64", "AMD64": "amd64"}[platform.machine()]
    cache = root / "local/debian-vm/cache"
    cache.mkdir(parents=True, exist_ok=True)
    base = image(cache, arch)
    work = Path(tempfile.mkdtemp(prefix=arch + "-", dir=cache.parent))
    work.chmod(0o700)
    print("Disposable Debian VM artifacts: " + str(work), flush=True)
    seed(work)
    source = packages / "source"
    shutil.copyfile(source / "ci/debian/vm/setup.sh", work / "setup.sh")
    debs = sorted(packages.glob("supivpn*.deb"))
    if len(debs) != 4 or any(p.is_symlink() for p in debs):
        raise ValueError("Expected exactly four locally built Debian packages")
    for path in debs:
        shutil.copyfile(path, work / path.name)
    env = dict(os.environ, CGO_ENABLED="0", GOOS="linux", GOARCH=arch, GOTOOLCHAIN="local",
               GOWORK="off", GOPROXY="off", GOSUMDB="off", GOPATH=str(root / "local/go"),
               GOCACHE=str(root / "local/build-cache"))
    run([go, "test", "-mod=vendor", "-buildvcs=false", "-c", "-tags=integration", "-o",
         str(work / "agent-vm.test"), "./internal/agent"], cwd=source, env=env)
    runner = "supivpn-debian-vm-test:" + host_arch
    run([docker, "build", "--platform", "linux/" + host_arch, "-t", runner,
         str(source / "ci/debian/vm")])
    common = [docker, "run", "--rm", "--pull", "never", "--cap-drop", "ALL",
              "--security-opt", "no-new-privileges", "--user", f"{os.getuid()}:{os.getgid()}",
              "--mount", f"type=bind,source={work},target=/work", "--workdir", "/work"]
    run(common + ["--platform", "linux/" + arch, "--network", "none",
                  "supivpn-debian-test:trixie-" + arch, "cp", "/opt/openvpn-test.deb", "/work/openvpn-test.deb"])
    tools = common + ["--platform", "linux/" + host_arch, "--network", "none",
                      "--mount", f"type=bind,source={base},target=/base.qcow2,readonly", runner]
    run(tools + ["qemu-img", "create", "-f", "qcow2", "-F", "qcow2", "-b", "/base.qcow2", "disk.qcow2", "12G"])
    run(tools + ["genisoimage", "-quiet", "-output", "seed.iso", "-volid", "cidata", "-joliet", "-rock", "user-data", "meta-data"])
    cpu = ["qemu-system-aarch64", "-machine", "virt", "-cpu", "max", "-bios", "/usr/share/qemu-efi-aarch64/QEMU_EFI.fd"] if arch == "arm64" else ["qemu-system-x86_64", "-machine", "q35", "-cpu", "max"]
    name = "supivpn-debian-vm-" + uuid.uuid4().hex[:12]
    start = common + ["--platform", "linux/" + host_arch, "--detach", "--name", name,
                      "--label", "supivpn.disposable-test=true", "--publish", "127.0.0.1::2222",
                      "--mount", f"type=bind,source={base},target=/base.qcow2,readonly", runner,
                      *cpu, "-accel", "tcg", "-smp", "2", "-m", "2048", "-display", "none",
                      "-monitor", "none", "-serial", "file:console.log",
                      "-drive", "file=disk.qcow2,if=virtio,format=qcow2",
                      "-drive", "file=seed.iso,if=virtio,format=raw,readonly=on",
                      "-nic", "user,model=virtio-net-pci,hostfwd=tcp:0.0.0.0:2222-:22"]
    container = run(start, capture_output=True, text=True).stdout.strip()
    database_container = None
    try:
        database_fixtures = None
        if database == "remote":
            database_container, database_fixtures = external_database(source, work, docker, container, host_arch)
        published = run([docker, "port", container, "2222/tcp"], capture_output=True, text=True).stdout.strip()
        if not published.startswith("127.0.0.1:"):
            raise ValueError("VM SSH must bind only to host loopback")
        port = str(int(published.split(":")[1]))
        (work / "known_hosts").write_text(f"[127.0.0.1]:{port} " + (work / "host.pub").read_text())
        options = ["-F", "/dev/null", "-i", str(work / "client"), "-o", "IdentityAgent=none",
                   "-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=yes", "-o",
                   "UserKnownHostsFile=" + str(work / "known_hosts"), "-o", "BatchMode=yes",
                   "-o", "ConnectTimeout=5"]
        ssh = ["ssh", *options, "-p", port, "root@127.0.0.1"]

        def wait_boot(previous=None):
            deadline = time.monotonic() + 600
            while time.monotonic() < deadline:
                result = subprocess.run(ssh + ["cat /proc/sys/kernel/random/boot_id"],
                                        capture_output=True, text=True, timeout=15)
                boot_id = result.stdout.strip()
                if result.returncode == 0 and boot_id and boot_id != previous:
                    return boot_id
                time.sleep(2)
            raise TimeoutError("Debian VM did not boot with the expected SSH host key")

        first_boot = wait_boot()
        run(ssh + ["install -d -m 700 /opt/supivpn-test"])
        uploads = [work / p.name for p in debs] + [work / p for p in ("setup.sh", "openvpn-test.deb", "agent-vm.test")]
        run(["scp", *options, "-P", port, *map(str, uploads), "root@127.0.0.1:/opt/supivpn-test/"])
        if database_fixtures:
            run(ssh + ["install -d -m 700 /opt/supivpn-test/database"])
            files = [database_fixtures / name for name in ("ca.pem", "runtime.password", "migration.password")]
            run(["scp", *options, "-P", port, *map(str, files), "root@127.0.0.1:/opt/supivpn-test/database/"])
        listed = run(ssh + ["/opt/supivpn-test/agent-vm.test -test.list='^TestDebianVM'"], capture_output=True, text=True)
        if set(listed.stdout.splitlines()) != {"TestDebianVMPrepare", "TestDebianVMServices", "TestDebianVMProfileBinding", "TestDebianVMAfterReboot", "TestDebianVMPackageLifecycle"}:
            raise ValueError("VM acceptance test binary is incomplete")
        print("VM: installing prerequisites and packages", flush=True)
        with (work / "install.log").open("w") as log:
            run(ssh + ["sh /opt/supivpn-test/setup.sh " + database], stdout=log, stderr=subprocess.STDOUT)
        test = ("SUPIVPN_TEST_DEBIAN_VM=1 SUPIVPN_TEST_VM_DATABASE=" + database +
                " /opt/supivpn-test/agent-vm.test -test.v -test.timeout=10m -test.run=")
        run(ssh + [test + "'^TestDebianVM(Prepare|Services)$'"])
        run(ssh + [test + "'^TestDebianVMProfileBinding$'"])
        print("VM: rebooting with services enabled", flush=True)
        run(ssh + ["systemctl reboot"])
        second_boot = wait_boot(first_boot)
        run(ssh + [test + "'^TestDebianVMAfterReboot$'"])
        run(ssh + [test + "'^TestDebianVMPackageLifecycle$'"])
        report = {"architecture": arch, "database_mode": database,
                  "image_version": IMAGE_VERSION, "image_sha512": IMAGE_SHA512[arch],
                  "first_boot_id": first_boot, "second_boot_id": second_boot,
                  "packages_sha256": {p.name: digest(p, "sha256") for p in debs}, "result": "passed"}
        (work / "result.json").write_text(json.dumps(report, indent=2) + "\n")
        print("PASS: Debian VM " + arch + "; evidence: " + str(work / "result.json"), flush=True)
    finally:
        # Exact ID returned by our own docker run; never clean up other resources.
        try:
            if database_container:
                subprocess.run([docker, "stop", "--time", "10", database_container], check=True,
                               timeout=30, stdout=subprocess.DEVNULL)
        finally:
            subprocess.run([docker, "stop", "--time", "5", container], check=True, timeout=30,
                           stdout=subprocess.DEVNULL)
