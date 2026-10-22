# Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
# SPDX-License-Identifier: AGPL-3.0-only
"""Validate operator inputs and fail-closed setup before any host mutation."""
import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import debian_setup as setup

REPO = Path(__file__).resolve().parents[1]


class SetupTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.config = self.root / "input.json"
        self.example = json.loads((REPO / "debian/examples/setup.example.json").read_text())
        self.config.write_text(json.dumps(self.example))

    def load(self, **changes):
        self.config.write_text(json.dumps(self.example | changes))
        return setup.configuration(self.config)

    def test_rejects_ambiguous_or_injectable_inputs(self):
        cases = [{"hostname": "vpn.example.test\nignored"}, {"hostname": "https://vpn.example.test"},
                 {"hostname": "-example.test"}, {"hostname": 123}, {"login_hostname": "host:8443"},
                 {"groups": []}, {"groups": ["admins", "admins"]}, {"groups": ["admins\nfoo"]},
                 {"groups": [" admins"]}, {"admin_cidr": "0.0.0.0/0"},
                 {"admin_cidr": "10.203.0.1/32"}, {"vpn_network": "8.8.0.0/16"},
                 {"vpn_network": "10.1.1.1/24"}, {"vpn_network": "10.1.0.0/30"},
                 {"ssh_port": True}, {"ssh_port": 8443}, {"database_name": "postgres"},
                 {"database_name": "supivpn;DROP DATABASE postgres"},
                 {"certificate_directory": "relative"}, {"idp_metadata_file": "/root/../file"},
                 {"unknown": "typo"}]
        for change in cases:
            with self.subTest(change=change), self.assertRaises((setup.SetupError, ValueError)):
                self.load(**change)
        self.config.write_text('{"hostname":"one","hostname":"two"}')
        with self.assertRaisesRegex(setup.SetupError, "Duplicate"):
            setup.configuration(self.config)

    def test_generated_config_has_one_authoritative_policy_and_real_uid(self):
        # Load real packaged examples through a temporary install layout.
        examples = self.root / "doc"
        for name, files in {"supivpn-node": ["agent.example.json", "server.conf.example"],
                            "supivpn-controller": ["controller.example.json"]}.items():
            dest = examples
            dest.mkdir(parents=True, exist_ok=True)
            for file in files:
                (dest / file).write_bytes((REPO / "debian/examples" / file).read_bytes())
        c = self.load(hostname="vpn.example.test", login_hostname="login.example.test",
                      vpn_network="10.99.0.0/24", groups=["vpn-team", "vpn-admin", "vpn-ops"])
        with patch.object(setup, "EXAMPLES", examples):
            agent, controller, server = setup.configs(c, 987)
        self.assertEqual(agent["remote_controller"]["controller_uid"], 987)
        self.assertEqual(agent["remote_controller"]["public_url"], controller["public_url"])
        self.assertEqual(controller["profile"]["endpoint"], "vpn.example.test")
        self.assertEqual(controller["database_tls"]["mode"], "verify-full")
        self.assertEqual(controller["database_tls"]["server_name"], "127.0.0.1")
        self.assertEqual([p["cidr"] for p in agent["group_pools"]],
                         ["10.99.0.0/26", "10.99.0.64/26", "10.99.0.128/26"])
        self.assertEqual([(p["group_name"], p["priority"]) for p in agent["group_pools"]],
                         [(g["name"], g["priority"]) for g in controller["groups"]])
        self.assertIn("server 10.99.0.0 255.255.255.0 nopool", server)
        rules = setup.firewall(c)
        self.assertIn("ip daddr 10.99.0.1", rules)
        self.assertIn("ip saddr 198.51.100.10/32 tcp dport 22 accept", rules)
        self.assertIn("type filter hook forward priority 0; policy drop", rules)

    def test_plan_never_runs_commands_or_creates_host_files(self):
        with patch.object(setup, "ROOT", self.root / "host"), patch.object(setup, "run") as run, \
                patch("sys.argv", ["supivpn-setup", "plan", "--config", str(self.config)]), \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(setup.main(), 0)
        run.assert_not_called()
        self.assertFalse((self.root / "host").exists())

    def test_existing_output_and_links_are_preserved(self):
        path = self.root / "key"
        path.write_text("synthetic sentinel")
        with self.assertRaises(setup.SetupError):
            setup.write(path, b"replacement")
        link = self.root / "link"
        link.symlink_to(path)
        with self.assertRaises(setup.SetupError):
            setup.write(link, b"replacement", replace=True)
        self.assertEqual(path.read_text(), "synthetic sentinel")

    def test_output_is_private_and_explicit_replacement_is_atomic(self):
        path = self.root / "credential"
        with patch("os.fchown"):
            setup.write(path, b"synthetic first")
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            setup.write(path, b"synthetic second", replace=True)
        self.assertEqual(path.read_bytes(), b"synthetic second")
        self.assertEqual(list(self.root.glob(".setup-*")), [])

    def test_existing_installation_refused_before_any_process(self):
        host = self.root / "host"
        host.mkdir()
        def read(path, limit):
            return b"13.1" if str(path) == "/etc/debian_version" else b"systemd\n"
        with patch.object(setup, "ROOT", host), patch.object(setup, "read", side_effect=read), \
                patch("os.geteuid", return_value=0), patch("sys.platform", "linux"), \
                patch.object(setup, "run") as run:
            with self.assertRaisesRegex(setup.SetupError, "Existing"):
                setup.preflight()
        run.assert_not_called()

    def test_command_failure_never_exposes_output_arguments_or_sql(self):
        secret = "sensitive-test-only"
        result = subprocess.CompletedProcess([], 1, secret.encode(), secret.encode())
        with patch("subprocess.run", return_value=result) as call:
            with self.assertRaises(setup.SetupError) as error:
                setup.run(["psql", secret], data=secret.encode(), env={"PGPASSWORD": secret})
        self.assertNotIn(secret, str(error.exception))
        self.assertNotIn("HOME", call.call_args.kwargs["env"])
        self.assertEqual(call.call_args.kwargs["env"]["PATH"], setup.ENV["PATH"])

    def test_invalid_input_report_does_not_echo_content(self):
        secret = "sensitive-test-only"
        self.config.write_text(secret)
        output = io.StringIO()
        with patch("sys.argv", ["supivpn-setup", "init", "--config", str(self.config)]), \
                contextlib.redirect_stderr(output), patch.object(setup, "initialize") as init:
            self.assertEqual(setup.main(), 1)
        init.assert_not_called()
        self.assertNotIn(secret, output.getvalue())

    def test_bad_certificate_stops_before_host_write_or_key_generation(self):
        with patch.object(setup, "preflight"), \
                patch.object(setup, "certificate_inputs", side_effect=setup.SetupError("certificate rejected")), \
                patch.object(setup, "directory") as mkdir, patch.object(setup, "database") as db:
            with self.assertRaisesRegex(setup.SetupError, "certificate rejected"):
                setup.initialize(self.load())
        mkdir.assert_not_called()
        db.assert_not_called()


if __name__ == "__main__":
    unittest.main()
