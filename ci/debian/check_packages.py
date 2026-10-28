#!/usr/bin/env python3
# Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
# SPDX-License-Identifier: AGPL-3.0-only
"""Destructive package lifecycle checks; run only in the disposable test image."""
import hashlib
import os
from pathlib import Path
import subprocess
import sys
import tempfile


def run(*args):
    return subprocess.check_output(args, text=True, stderr=subprocess.STDOUT)


def check(packages):
    if not Path("/.dockerenv").exists() or os.geteuid() != 0:
        raise RuntimeError("This check requires the disposable root test container")
    arch = run("dpkg", "--print-architecture").strip()
    files = {name: next(packages.glob(name + "_*.deb")) for name in
             ("supivpn", "supivpn-node", "supivpn-controller", "supivpn-cli")}
    version = run("dpkg-deb", "-f", str(files["supivpn"]), "Version").strip()
    # Go's static runtime is documented by narrowly scoped package overrides.
    # All other binary-package lintian warnings and errors must be addressed.
    print(run("lintian", "--allow-root", "--fail-on", "error,warning",
              *(str(p) for p in files.values())), end="")
    for name, deb in files.items():
        expected = "all" if name == "supivpn" else arch
        assert run("dpkg-deb", "-f", str(deb), "Architecture").strip() == expected
        assert run("dpkg-deb", "-f", str(deb), "Version").strip() == version
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run("dpkg-deb", "-x", str(deb), str(root))
            run("dpkg-deb", "-e", str(deb), str(root / "DEBIAN"))
            assert not (root / "etc").exists(), "active configuration in package"
            assert not (root / "var").exists(), "runtime state in package"
            for binary in (root / "usr/sbin").glob("*"):
                header = binary.read_bytes()[:20]
                if name == "supivpn" and binary.name == "supivpn-setup":
                    assert header.startswith(b"#!/usr/bin/python3\n")
                    assert binary.stat().st_mode & 0o777 == 0o755
                    run("python3", str(binary), "--help")
                    continue
                assert header[:4] == b"\x7fELF"
                assert int.from_bytes(header[18:20], "little") == {"arm64": 183, "amd64": 62}[arch]
                assert binary.stat().st_mode & 0o777 == 0o755
                assert "statically linked" in run("file", str(binary))
            for sql in (root / "usr/share/supivpn-controller/migrations").glob("*.sql"):
                original = packages / "source/internal/postgres/migrations" / sql.name
                assert sql.read_bytes() == original.read_bytes(), "migration changed during packaging"
            for script in (root / "DEBIAN").iterdir():
                if script.name in {"preinst", "postinst", "prerm", "postrm"}:
                    text = script.read_text()
                    assert "supivpn-migrate" not in text
                    assert "tls-crypt" not in text
                    assert "curl " not in text and "wget " not in text
                    run("sh", "-n", str(script))
    controller_deps = run("dpkg-deb", "-f", str(files["supivpn-controller"]), "Depends")
    assert "openvpn" not in controller_deps and "postgresql" not in controller_deps
    assert "supivpn-controller" not in run("dpkg-deb", "-f", str(files["supivpn-node"]), "Depends")
    deps = run("dpkg-deb", "-f", str(files["supivpn"]), "Depends")
    for name in ("supivpn-node", "supivpn-controller", "supivpn-cli"):
        assert f"{name} (= {version})" in deps

    # Debian helpers run against real dpkg state. No systemd manager or network
    # is present; a policy guard additionally prevents accidental service starts.
    policy = Path("/usr/sbin/policy-rc.d")
    policy.write_text("#!/bin/sh\nexit 101\n")
    policy.chmod(0o755)
    # Exercise generated maintainer scripts' running-systemd branches without
    # starting services. This records lifecycle requests, not daemon behavior.
    calls = Path("/tmp/supivpn-service-calls")
    wrappers = Path("/tmp/supivpn-service-tools")
    wrappers.mkdir()
    for name in ("systemctl", "deb-systemd-invoke"):
        script = wrappers / name
        enumeration = ''
        if name == "systemctl":
            enumeration = ('if [ "$1" = list-units ]; then\n'
                           '  printf "%s\\n" "supivpn-node@bound.service loaded active running" '
                           '"supivpn-openvpn@bound.service loaded active running" '
                           '"unrelated.service loaded active running"\nfi\n')
        script.write_text('#!/bin/sh\nprintf "%s %s\\n" "' + name + '" "$*" >> ' + str(calls) + '\n' + enumeration + 'exit 0\n')
        script.chmod(0o755)
    Path("/run/systemd/system").mkdir(parents=True)
    os.environ["PATH"] = str(wrappers) + ":" + os.environ["PATH"]

    def no_lifecycle_requests():
        text = calls.read_text() if calls.exists() else ""
        assert "deb-systemd-invoke" not in text, "install/upgrade requested a service change"
        for line in text.splitlines():
            assert not {"start", "stop", "restart", "try-restart", "reload", "reload-or-restart"}.intersection(line.split()), line
        calls.write_text("")

    run("dpkg", "-i", str(files["supivpn-controller"]))
    no_lifecycle_requests()
    assert not Path("/usr/sbin/openvpn").exists(), "controller pulled in OpenVPN"
    assert "supivpn-controller" in run("getent", "passwd", "supivpn-controller")
    disabled = subprocess.run(["/usr/bin/systemctl", "--root=/", "is-enabled", "supivpn-controller.service"],
                              capture_output=True, text=True)
    assert disabled.returncode == 1 and disabled.stdout.strip() == "disabled"
    assert not list(Path("/etc/systemd/system").glob("*.wants/supivpn*.service"))
    run("dpkg", "-i", "/opt/openvpn-test.deb", str(files["supivpn-node"]), str(files["supivpn-cli"]), str(files["supivpn"]))
    run("/usr/sbin/supivpn-cli", "--help")
    no_lifecycle_requests()
    run("supivpn-setup", "plan", "--config", "/usr/share/supivpn/examples/setup.example.json")
    assert not Path("/etc/supivpn").exists(), "plan changed the host"
    run("systemd-analyze", "verify", "supivpn-node.service", "supivpn-openvpn.service", "supivpn-controller.service",
        "supivpn-openvpn-tcp.service", "supivpn-node@bound.service", "supivpn-openvpn@bound.service")
    # Operator files are synthetic sentinels, never credentials.
    sentinels = [Path("/etc/supivpn/node/operator-sentinel"),
                 Path("/etc/supivpn/controller/operator-sentinel"),
                 Path("/etc/supivpn/keys/operator-sentinel"),
                 Path("/var/lib/supivpn-node/operator-sentinel"),
                 Path("/etc/supivpn/nodes/bound/operator-sentinel"),
                 Path("/var/lib/supivpn-node-bound/operator-sentinel")]
    for path in sentinels:
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        path.write_text("package lifecycle sentinel\n")
        path.chmod(0o600)
    baseline = {p: (hashlib.sha256(p.read_bytes()).hexdigest(), p.stat().st_mode) for p in sentinels}
    run("/usr/bin/systemctl", "--root=/", "enable", "supivpn-node.service", "supivpn-controller.service")
    run("dpkg", "-i", *(str(p) for p in files.values()))
    run("dpkg-reconfigure", "-f", "noninteractive", "supivpn-controller")
    no_lifecycle_requests()
    # A distinct version makes dpkg exercise upgrade paths, not just reinstall.
    with tempfile.TemporaryDirectory() as directory:
        upgraded = []
        for name, deb in files.items():
            unpacked = Path(directory) / name
            run("dpkg-deb", "-R", str(deb), str(unpacked))
            control = unpacked / "DEBIAN/control"
            control.write_text(control.read_text().replace(version, version + "+test1"))
            target = Path(directory) / (name + ".deb")
            run("dpkg-deb", "--build", "--root-owner-group", str(unpacked), str(target))
            upgraded.append(str(target))
        run("dpkg", "-i", *upgraded)
    no_lifecycle_requests()
    for name in ("supivpn-node", "supivpn-controller"):
        assert run("/usr/bin/systemctl", "--root=/", "is-enabled", name + ".service").strip() == "enabled"
    run("dpkg", "-r", "supivpn")
    no_lifecycle_requests()
    assert Path("/usr/sbin/supivpn").exists() and Path("/usr/sbin/supivpn-controller").exists()
    run("dpkg", "--purge", "supivpn-node", "supivpn-controller", "supivpn-cli", "supivpn")
    stopped = [line for line in calls.read_text().splitlines() if line.startswith("deb-systemd-invoke")]
    assert len(stopped) == 4, stopped
    assert any("stop supivpn-controller.service" in line for line in stopped), stopped
    assert any("supivpn-node.service" in line and "supivpn-openvpn.service" in line for line in stopped), stopped
    assert any("supivpn-openvpn-tcp.service" in line for line in stopped), stopped
    assert "deb-systemd-invoke stop supivpn-node@bound.service" in stopped, stopped
    assert "deb-systemd-invoke stop supivpn-openvpn@bound.service" in stopped, stopped
    assert all("unrelated.service" not in line for line in stopped), stopped
    assert {p: (hashlib.sha256(p.read_bytes()).hexdigest(), p.stat().st_mode) for p in sentinels} == baseline
    assert run("getent", "passwd", "supivpn-controller")
    assert not list(Path("/etc/systemd/system").glob("*.wants/supivpn*.service"))
    print(f"Debian {arch}: payloads, dependencies, units, install/reconfigure/upgrade/remove/purge passed")
    print("No running-systemd, reboot or VPN network acceptance is claimed by this check.")


if __name__ == "__main__":
    check(Path(sys.argv[1]))
