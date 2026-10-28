#!/usr/bin/env python3
# Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
# Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
# SPDX-License-Identifier: AGPL-3.0-only
"""Run the packaged OpenVPN 3 Linux client in a disposable network namespace."""
import os
from pathlib import Path
import subprocess
import time


def main():
    os.makedirs('/run/dbus', exist_ok=True)
    # A synthetic container identity, never a host machine ID or mounted data.
    subprocess.run(['dbus-uuidgen', '--ensure=/etc/machine-id'], check=True)
    processes = []
    try:
        processes.append(subprocess.Popen(
            ['dbus-daemon', '--system', '--nofork', '--nopidfile'],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
        deadline = time.monotonic() + 10
        while not Path('/run/dbus/system_bus_socket').exists():
            if time.monotonic() >= deadline:
                raise RuntimeError('D-Bus startup failed')
            time.sleep(0.05)
        for command in (
                ['/usr/libexec/openvpn3-linux/openvpn3-service-log', '--log-level', '3'],
                ['/lib/systemd/systemd-hostnamed'],
                ['/usr/libexec/openvpn3-linux/openvpn3-service-netcfg']):
            processes.append(subprocess.Popen(command, stdout=subprocess.DEVNULL,
                                               stderr=subprocess.DEVNULL))
        time.sleep(1)
        return subprocess.run(['/test/openvpn.test', '-test.run', '^TestOpenVPN(TLSCryptV2|TransportFallback)$',
                               '-test.v', '-test.timeout', '180s'], check=False).returncode
    finally:
        for process in reversed(processes):
            if process.poll() is None:
                process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)


if __name__ == '__main__':
    raise SystemExit(main())
