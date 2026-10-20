# Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
# Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
# SPDX-License-Identifier: AGPL-3.0-only
"""Exercise recursive Go discovery with a downloaded pre-module dependency."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


@unittest.skipUnless(shutil.which("go") and shutil.which("make"), "Go and Make required")
class WorkspaceBoundaryTests(unittest.TestCase):
    def test_make_excludes_cached_source_and_preserves_existing_boundary(self):
        makefile = Path(__file__).resolve().parents[1] / "Makefile"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "go.mod").write_text("module workspace.test\n\ngo 1.20\n")
            (root / "main.go").write_text("package main\nfunc main() {}\n")
            cached = root / "local/go/pkg/mod/old.test/library@v1.0.0"
            cached.mkdir(parents=True)
            (cached / "library.go").write_text("package library\n")
            env = dict(os.environ, GOWORK="off", GOTOOLCHAIN="local", GOPROXY="off",
                       GOSUMDB="off", GOPATH=str(root / "local/go"),
                       GOCACHE=str(root / "local/build-cache"))
            subprocess.run(["make", "-f", str(makefile), "deps-verify"], cwd=root,
                           env=env, check=True, capture_output=True, timeout=30)
            result = subprocess.run(["go", "list", "./..."], cwd=root, env=env,
                                    check=True, capture_output=True, text=True, timeout=30)
            self.assertEqual(result.stdout.strip(), "workspace.test")
            boundary = root / "local/go.mod"
            self.assertEqual(boundary.read_text(), "module supivpn-local-artifacts\n")
            boundary.write_text("module operator-local-artifacts\n")
            subprocess.run(["make", "-f", str(makefile), "deps-verify"], cwd=root,
                           env=env, check=True, capture_output=True, timeout=30)
            self.assertEqual(boundary.read_text(), "module operator-local-artifacts\n")


if __name__ == "__main__":
    unittest.main()
