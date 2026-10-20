# Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
# Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
# SPDX-License-Identifier: AGPL-3.0-only
"""Wait for the health check of one newly created disposable test container."""
import argparse
import json
import math
import re
import shlex
import subprocess
import sys
import time


def wait_healthy(docker, container, timeout):
    if not re.fullmatch(r"[a-f0-9]{64}", container):
        raise ValueError("Docker did not return a full container ID")
    if not math.isfinite(timeout) or timeout <= 0:
        raise ValueError("Readiness timeout must be a positive number of seconds")
    command = shlex.split(docker)
    if not command:
        raise ValueError("Docker command is empty")
    deadline = time.monotonic() + timeout
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ValueError("Timed out waiting for the test database to become healthy")
        try:
            result = subprocess.run(
                [*command, "inspect", "--format", "{{json .State}}", container],
                capture_output=True, text=True, timeout=min(5, remaining), check=True)
            state = json.loads(result.stdout)
        except (OSError, subprocess.SubprocessError, ValueError):
            raise ValueError("Cannot inspect the new test container; it may have exited") from None
        health = state.get("Health", {}) if isinstance(state, dict) else {}
        status = health.get("Status") if isinstance(health, dict) else None
        if not isinstance(state, dict) or state.get("Running") is not True:
            raise ValueError("The new test container stopped before becoming ready")
        if status == "healthy":
            return
        if status != "starting":
            raise ValueError("The new test container has no healthy or starting health check")
        time.sleep(min(0.5, max(0, deadline - time.monotonic())))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--docker", default="docker")
    parser.add_argument("--timeout", type=float, default=60)
    parser.add_argument("container")
    args = parser.parse_args()
    try:
        wait_healthy(args.docker, args.container, args.timeout)
    except ValueError as error:
        print(str(error) + "; inspect or stop the disposable container before retrying.", file=sys.stderr)
        return 1
    print("Disposable PostgreSQL is healthy and ready for integration tests.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
