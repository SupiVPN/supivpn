# Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
# SPDX-License-Identifier: AGPL-3.0-only
"""Validate operator inputs and fail-closed setup before any host mutation."""
import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import stat
import tempfile
from types import SimpleNamespace
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

    def test_tcp_fallback_uses_one_agent_identity_and_aggregate(self):
        c = self.load(tcp_fallback={"enabled": True}, groups=["admins", "engineers"])
        with patch.object(setup, "EXAMPLES", REPO / "debian/examples"):
            agent, controller, server = setup.configs(c, 987)
            tcp_server = setup.tcp_server_config(c, server)
        self.assertEqual(controller["profile"]["tcp_fallback_port"], 443)
        self.assertEqual(controller["profile"]["binding"], "required")
        self.assertEqual(agent["profile_binding"], "required")
        self.assertEqual(agent["vpn_network"], "10.203.0.0/24")
        self.assertNotIn("additional_agents", controller["vm"])
        self.assertEqual(agent["remote_controller"]["node_id"], controller["vm"]["node_id"])
        self.assertEqual(agent["group_pools"][0]["cidr"], "10.203.0.0/25")
        self.assertEqual(agent["group_pools"][1]["cidr"], "10.203.0.128/25")
        self.assertIn("port 443\nproto tcp4-server\n", tcp_server)
        self.assertIn("server 10.203.0.0 255.255.255.0 nopool", server)
        self.assertIn("server 10.203.0.0 255.255.255.0 nopool", tcp_server)
        self.assertIn('-learn-address -route-device supivpn0 -route-network 10.203.0.0/24', server)
        self.assertIn('-learn-address -route-device supivpn1 -route-network 10.203.0.0/24', tcp_server)
        self.assertIn('client-disconnect "/usr/sbin/supivpn -route-disconnect', tcp_server)
        self.assertIn(agent["tcp_management_socket"], tcp_server)
        for configuration in (server, tcp_server):
            self.assertIn('-verify-profile-metadata required', configuration)
            self.assertIn('tls-crypt-v2 /etc/supivpn/keys/tls-crypt-v2-server.key', configuration)
        rules = setup.firewall(c)
        self.assertIn("udp dport 1194 accept", rules)
        self.assertIn("tcp dport 443 accept", rules)
        self.assertLess(rules.index('iifname "supivpn1" drop'), rules.index("ct state established"))
        self.assertEqual(setup.service_units(c), ["supivpn-controller", "supivpn-node", "supivpn-openvpn", "supivpn-openvpn-tcp"])
        plain = self.load()
        self.assertNotIn("tcp dport 443", setup.firewall(plain))
        self.assertNotIn("supivpn-openvpn-tcp", setup.service_units(plain))
        for value in ({}, {"enabled": False}, {"enabled": False, "port": 443}):
            disabled = self.load(tcp_fallback=value)
            self.assertNotIn("tcp_fallback", disabled)
            with patch.object(setup, "EXAMPLES", REPO / "debian/examples"):
                a, ctl, cfg = setup.configs(disabled, 987)
            self.assertNotIn("tcp_management_socket", a)
            self.assertNotIn("tcp_fallback_port", ctl["profile"])
            self.assertNotIn("route-device", cfg)
            self.assertNotIn("supivpn1", setup.firewall(disabled))
        # A disabled optional listener must not reserve the operator's SSH port.
        self.load(ssh_port=443, tcp_fallback={"enabled": False, "port": 443})

    def test_tcp_rejects_conflicts_and_ambiguous_inputs(self):
        for value in (True, None, {"enabled": "true"}, {"vpn_network": "10.204.0.0/24"},
                      {"port": True}, {"enabled": True, "port": 8443}, {"enabled": True, "port": 22}, {"port": 0},
                      {"port": 65536}, {"port": 443, "typo": 1}):
            with self.subTest(value=value), self.assertRaises((setup.SetupError, ValueError)):
                self.load(tcp_fallback=value)
        # Enabling TCP must not impose an additional per-transport pool limit.
        self.load(tcp_fallback={"enabled": True}, vpn_network="10.203.0.0/26", groups=["a","b","c","d"])

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

    def remote(self, **changes):
        return self.load(database={
            "host": "db.example.test", "ca_file": str(self.root / "ca.pem"),
            "runtime_password_file": str(self.root / "runtime"),
            "migration_password_file": str(self.root / "migrator"),
        } | changes)

    def test_remote_configuration_rejects_unknown_fields_and_unsafe_endpoints(self):
        for change in ({"host": "db.test sslmode=disable"}, {"host": "/tmp/socket"},
                       {"host": "https://db.test"}, {"port": True}, {"port": 0},
                       {"port": 65536}, {"sslmode": "disable"},
                       {"runtime_password_file": "relative"},
                       {"ca_file": "/root/../ca.pem"}):
            with self.subTest(change=change), self.assertRaises(setup.SetupError):
                self.remote(**change)
        for value in (None, {}, "db.test"):
            with self.subTest(value=value), self.assertRaises(setup.SetupError):
                self.load(database=value)
        c = self.remote()
        self.assertEqual(c["database"]["port"], 5432)
        with patch.object(setup, "EXAMPLES", REPO / "debian/examples"):
            _, controller, _ = setup.configs(c, 987)
        self.assertEqual(controller["database_tls"]["mode"], "verify-full")
        self.assertEqual(controller["database_tls"]["server_name"], "db.example.test")

    def test_remote_plan_does_not_open_credentials_or_connect(self):
        self.remote()
        with patch.object(setup, "remote_inputs") as inputs, patch.object(setup, "run") as run, \
                patch("sys.argv", ["supivpn-setup", "plan", "--config", str(self.config)]), \
                contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(setup.main(), 0)
        inputs.assert_not_called()
        run.assert_not_called()
        self.assertIn("No local database cluster", output.getvalue())

    def test_remote_preflight_leaves_existing_local_database_and_port_alone(self):
        c = self.remote()
        local_config = self.load()
        def read(path, limit):
            return b"13.1" if str(path) == "/etc/debian_version" else b"systemd\n"
        def command(args):
            if args[0] == "dpkg-query":
                return b"install ok installed 0.6.0\n" * 3
            return b"OpenVPN 2.7.8 test"
        user = SimpleNamespace(pw_uid=987, pw_dir="/nonexistent", pw_shell="/usr/sbin/nologin")
        with patch.object(setup, "read", side_effect=read), patch.object(setup, "run", side_effect=command), \
                patch("os.geteuid", return_value=0), patch("sys.platform", "linux"), \
                patch.object(Path, "exists", autospec=True, side_effect=lambda path: path == setup.PG), \
                patch.object(Path, "is_symlink", return_value=False), \
                patch.object(Path, "is_file", autospec=True, side_effect=lambda path: str(path) == setup.PSQL), \
                patch.object(Path, "stat", return_value=SimpleNamespace(st_mode=stat.S_IFCHR)), \
                patch.object(setup.pwd, "getpwnam", return_value=user), \
                patch.object(setup.socket, "socket") as socket:
            self.assertEqual(setup.preflight(c), user)
            binds = socket.return_value.__enter__.return_value.bind.call_args_list
            self.assertNotIn((("127.0.0.1", setup.PORT),), [call.args for call in binds])
            with self.assertRaisesRegex(setup.SetupError, "Existing"):
                setup.preflight(local_config)

    def test_remote_init_selects_only_remote_database(self):
        c = self.remote()
        host = self.root / "installed"
        metadata = b'<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="test"/>'
        c["idp_metadata_file"] = str(self.root / "idp.xml")
        Path(c["idp_metadata_file"]).write_bytes(metadata)
        user = SimpleNamespace(pw_uid=os.getuid(), pw_gid=os.getgid())
        def command(args, **kwargs):
            if args[0] == "/usr/sbin/supivpn-profile":
                Path(args[-1]).write_text("synthetic wrapping-key sentinel")
            return b""
        with patch.object(setup, "ROOT", host), patch.object(setup, "EXAMPLES", REPO / "debian/examples"), \
                patch.object(setup, "preflight", return_value=user), \
                patch.object(setup, "certificate_inputs", return_value=({}, b"template")), \
                patch.object(setup, "remote_inputs", return_value={"synthetic": True}), \
                patch.object(setup, "verify_remote_database"), patch.object(setup, "run", side_effect=command), \
                patch.object(setup, "remote_database") as remote, patch.object(setup, "database") as local, \
                patch("os.chown"), patch("os.fchown"), patch("os.umask"), \
                contextlib.redirect_stdout(io.StringIO()):
            setup.initialize(c)
        remote.assert_called_once_with(c, user.pw_gid, {"synthetic": True})
        local.assert_not_called()
        self.assertTrue((host / "setup-complete").is_file())
        installed = json.loads((host / "controller/controller.json").read_text())
        self.assertEqual(installed["database_tls"]["server_name"], "db.example.test")

    def test_password_input_requires_private_regular_owned_file(self):
        path = self.root / "password"
        path.write_bytes(b"synthetic pass'\\word\"$\n")
        path.chmod(0o600)
        self.assertEqual(setup.password_input(path), "synthetic pass'\\word\"$")
        path.chmod(0o640)
        with self.assertRaises(setup.SetupError):
            setup.password_input(path)
        path.chmod(0o600)
        with patch("os.geteuid", return_value=path.stat().st_uid + 1), self.assertRaises(setup.SetupError):
            setup.password_input(path)
        link = self.root / "password-link"
        link.symlink_to(path)
        with self.assertRaises(OSError):
            setup.password_input(link)
        fifo = self.root / "fifo"
        os.mkfifo(fifo, 0o600)
        with self.assertRaises(setup.SetupError):
            setup.password_input(fifo)
        for value in (b"", b"\n", b"a\nb", b"a\r\n", b"\xff", b"a" * 4097):
            path.write_bytes(value)
            with self.assertRaises(setup.SetupError):
                setup.password_input(path)

    def test_remote_inputs_reject_private_key_or_shared_password(self):
        c = self.remote()
        with patch.object(setup, "read", return_value=b"synthetic PRIVATE KEY marker"), \
                patch.object(setup, "password_input", side_effect=["one", "two"]), \
                self.assertRaisesRegex(setup.SetupError, "public certificates"):
            setup.remote_inputs(c)
        with patch.object(setup, "read", return_value=b"public CA"), \
                patch.object(setup, "password_input", return_value="same"), \
                self.assertRaisesRegex(setup.SetupError, "different"):
            setup.remote_inputs(c)

    def test_remote_failure_precedes_all_host_writes(self):
        c = self.remote()
        metadata = b'<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="test"/>'
        with patch.object(setup, "preflight"), \
                patch.object(setup, "certificate_inputs", return_value=({}, b"")), \
                patch.object(setup, "read", return_value=metadata), \
                patch.object(setup, "remote_inputs", return_value={}), \
                patch.object(setup, "verify_remote_database", side_effect=setup.SetupError("rejected")), \
                patch.object(setup, "directory") as mkdir, patch.object(setup, "write") as write, \
                patch.object(setup, "run") as run:
            with self.assertRaisesRegex(setup.SetupError, "rejected"):
                setup.initialize(c)
        mkdir.assert_not_called()
        write.assert_not_called()
        run.assert_not_called()

    def test_remote_queries_use_verified_tls_and_private_environment(self):
        c = self.remote()
        with patch.object(setup, "run", return_value=b"t\n") as run:
            setup.verify_remote_database(c, {"runtime": "synthetic-one", "migrator": "synthetic-two"})
        self.assertEqual(run.call_count, 2)
        for call in run.call_args_list:
            self.assertNotIn("synthetic", " ".join(call.args[0]))
            env = call.kwargs["env"]
            self.assertEqual(env["PGSSLMODE"], "verify-full")
            self.assertEqual(env["PGHOST"], "db.example.test")
            self.assertEqual(env["PGCONNECT_TIMEOUT"], "5")
        for result in (b"f", b"", b"t\nf"):
            with patch.object(setup, "remote_query", return_value=result), self.assertRaises(setup.SetupError):
                setup.verify_remote_database(c, {})

    def test_remote_credentials_are_quoted_and_private(self):
        host = self.root / "installed"
        (host / "controller").mkdir(parents=True)
        c = self.remote()
        credentials = {"ca": b"public synthetic CA", "runtime": "test ' \\ \" $ value", "migrator": "different"}
        with patch.object(setup, "ROOT", host), patch("os.fchown"), \
                patch.object(setup, "run") as run, patch.object(setup, "remote_query", return_value=b"t"):
            setup.remote_database(c, os.getgid(), credentials)
        self.assertEqual(run.call_count, 1)
        self.assertEqual(run.call_args.args[0], ["/usr/sbin/supivpn-migrate"])
        for filename in ("database.env", "migration.env"):
            path = host / "controller" / filename
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            dsn = json.loads(path.read_text().split("=", 1)[1])
            self.assertIn("host='db.example.test'", dsn)
        self.assertIn("sslmode='verify-full'", run.call_args.kwargs["env"]["SUPIVPN_DATABASE_URL"])
        self.assertEqual((host / "controller/database-ca.pem").stat().st_mode & 0o777, 0o640)

    def test_remote_readiness_does_not_require_local_postgres_or_input_passwords(self):
        with patch.object(setup, "run") as run, patch.object(setup, "remote_inputs") as inputs, \
                contextlib.redirect_stdout(io.StringIO()):
            setup.check(self.remote())
        inputs.assert_not_called()
        commands = [call.args[0] for call in run.call_args_list]
        self.assertEqual([c[-1] for c in commands if c[0] == "systemctl"],
                         ["supivpn-controller", "supivpn-node", "supivpn-openvpn"])
        self.assertEqual(len([c for c in commands if c[0] == "curl"]), 2)


if __name__ == "__main__":
    unittest.main()
