# Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
# Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
# SPDX-License-Identifier: AGPL-3.0-only
"""Exercise local Make commands without a Docker daemon or working database."""
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
CONTAINER = "a" * 64
FAKE_DOCKER = '''import json, os, sys, time
from pathlib import Path
args = sys.argv[1:]
with open(os.environ["FAKE_DOCKER_LOG"], "a") as log:
    log.write(json.dumps(args) + "\\n")
if args[0] == "run":
    if os.environ.get("FAKE_DOCKER_FAIL_START") == "1": sys.exit(1)
    print("a" * 64)
elif args[0] == "inspect":
    path = Path(os.environ["FAKE_DOCKER_STATES"])
    states = json.loads(path.read_text())
    state = states.pop(0) if len(states) > 1 else states[0]
    path.write_text(json.dumps(states))
    if state == "missing": sys.exit(1)
    if state == "slow": time.sleep(5)
    print(json.dumps({"Running": state != "exited", "Health": {"Status": state}}))
else:
    sys.exit("Unexpected Docker operation")
'''


@unittest.skipUnless(shutil.which("make"), "Make required")
class LocalSetupTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        shutil.copy(ROOT / "Makefile", self.root / "Makefile")
        (self.root / "tools").mkdir()
        shutil.copy(ROOT / "tools/wait_container.py", self.root / "tools/wait_container.py")
        self.fake = self.root / "fake_docker.py"
        self.fake.write_text(FAKE_DOCKER)
        self.log = self.root / "docker.jsonl"
        self.states = self.root / "states.json"

    def start(self, states, *, fail=False, timeout="2", extra=()):
        self.states.write_text(json.dumps(states))
        env = dict(os.environ, FAKE_DOCKER_LOG=str(self.log), FAKE_DOCKER_STATES=str(self.states),
                   FAKE_DOCKER_FAIL_START="1" if fail else "0")
        docker = shlex.join([sys.executable, str(self.fake)])
        result = subprocess.run(["make", "--no-print-directory", "postgres-start", "DOCKER=" + docker,
                                 "PYTHON=" + shlex.quote(sys.executable), "POSTGRES_WAIT_TIMEOUT=" + timeout,
                                 *extra], cwd=self.root, env=env, capture_output=True, text=True, timeout=8)
        calls = [json.loads(line) for line in self.log.read_text().splitlines()]
        return result, calls

    def test_start_waits_for_its_new_container_and_preserves_test_isolation(self):
        result, calls = self.start(["starting", "healthy"],
                                   extra=("ARCH=amd64", "POSTGRES_CONTAINER=custom-test", "POSTGRES_PORT=55439"))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("healthy", result.stdout)
        self.assertEqual([call[0] for call in calls], ["run", "inspect", "inspect"])
        self.assertIn("127.0.0.1:55439:5432", calls[0])
        self.assertIn("supivpn.disposable-test=true", calls[0])
        self.assertIn("POSTGRES_DB=supivpn_test", calls[0])
        self.assertEqual(calls[0][calls[0].index("--name") + 1], "custom-test")
        self.assertEqual(calls[0][calls[0].index("--platform") + 1], "linux/amd64")
        self.assertTrue(all(call[-1] == CONTAINER for call in calls[1:]))

    def test_creation_failure_does_not_inspect_or_modify_an_existing_container(self):
        result, calls = self.start(["healthy"], fail=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual([call[0] for call in calls], ["run"])

    def test_startup_failures_and_timeout_are_bounded_without_cleanup(self):
        for state in ("unhealthy", "exited", "missing", "starting", "slow"):
            with self.subTest(state=state):
                if self.log.exists():
                    self.log.unlink()
                result, calls = self.start([state], timeout="0.2")
                self.assertNotEqual(result.returncode, 0)
                self.assertTrue(all(call[0] in {"run", "inspect"} for call in calls))
                self.assertIn("disposable container", result.stderr)

    def test_default_architecture_is_native_and_cross_build_override_is_preserved(self):
        native = {"x86_64": "amd64", "aarch64": "arm64", "arm64": "arm64"}.get(os.uname().machine)
        if native is None:
            self.skipTest("Host architecture is outside the supported ARM64/AMD64 matrix")
        result, calls = self.start(["healthy"])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(calls[0][calls[0].index("--platform") + 1], "linux/" + native)


if __name__ == "__main__":
    unittest.main()
