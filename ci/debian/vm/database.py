# Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
# SPDX-License-Identifier: AGPL-3.0-only
"""A disposable PostgreSQL server outside the Debian guest, reachable via QEMU."""
import os
from pathlib import Path
import pwd
import signal
import subprocess
import tempfile

BIN = "/usr/lib/postgresql/18/bin/"
FIXTURES = Path("/fixture")


def stop(*_):
    raise SystemExit(0)


def run(args, data=None):
    # SQL, generated credentials and server diagnostics must not reach logs.
    result = subprocess.run(args, input=data, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=60)
    if result.returncode:
        raise RuntimeError("Disposable database fixture command failed: " + Path(args[0]).name)


def serve(root):
    pg = pwd.getpwnam("postgres")
    root.chmod(0o755)
    data = root / "data"
    data.mkdir(mode=0o700)
    os.chown(data, pg.pw_uid, pg.pw_gid)
    postgres = ["runuser", "-u", "postgres", "--"]
    run(postgres + [BIN + "initdb", "-D", str(data), "--auth-local=trust", "--auth-host=scram-sha-256"])
    run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
         "-subj", "/CN=db.supivpn.test", "-addext", "subjectAltName=DNS:db.supivpn.test",
         "-keyout", str(data / "server.key"), "-out", str(data / "server.crt")])
    (data / "server.key").chmod(0o600)
    os.chown(data / "server.key", pg.pw_uid, pg.pw_gid)
    (data / "pg_hba.conf").write_text(
        "local all all trust\nhostssl supivpn_test all 127.0.0.1/32 scram-sha-256\n")
    with (data / "postgresql.conf").open("a") as stream:
        stream.write("\nlisten_addresses='127.0.0.1'\nssl=on\n"
                     "ssl_cert_file='server.crt'\nssl_key_file='server.key'\n"
                     "log_statement='none'\nlog_min_error_statement='panic'\n")
    run(postgres + [BIN + "pg_ctl", "-D", str(data), "-l", str(data / "server.log"), "-w", "start"])
    try:
        run(postgres + [BIN + "createdb", "-h", "/var/run/postgresql", "supivpn_test"])
        psql = postgres + [BIN + "psql", "-X", "-w", "-h", "/var/run/postgresql",
                           "-d", "supivpn_test", "-v", "ON_ERROR_STOP=1"]
        run(psql, b"""CREATE ROLE supivpn_owner NOLOGIN NOINHERIT;
CREATE ROLE supivpn_runtime LOGIN NOINHERIT;
CREATE ROLE supivpn_migrator LOGIN NOINHERIT;
GRANT supivpn_owner TO supivpn_migrator;
REVOKE ALL ON DATABASE supivpn_test FROM PUBLIC;
GRANT CONNECT, CREATE ON DATABASE supivpn_test TO supivpn_owner;
GRANT CONNECT ON DATABASE supivpn_test TO supivpn_runtime, supivpn_migrator;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT USAGE, CREATE ON SCHEMA public TO supivpn_owner;
CREATE SCHEMA supivpn AUTHORIZATION supivpn_owner;
GRANT USAGE ON SCHEMA supivpn TO supivpn_runtime;
ALTER DEFAULT PRIVILEGES FOR ROLE supivpn_owner IN SCHEMA supivpn
 GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO supivpn_runtime;
ALTER DEFAULT PRIVILEGES FOR ROLE supivpn_owner IN SCHEMA public
 GRANT SELECT ON TABLES TO supivpn_runtime;""")
        for role, filename in (("runtime", "runtime.password"), ("migrator", "migration.password")):
            password = (FIXTURES / filename).read_text()
            run(psql, ("ALTER ROLE supivpn_" + role + " PASSWORD '" + password.replace("'", "''") + "';").encode())
        (FIXTURES / "ca.pem").write_bytes((data / "server.crt").read_bytes())
        (FIXTURES / "ready").write_text("PostgreSQL 18 with verified TLS fixture\n")
        signal.signal(signal.SIGTERM, stop)
        signal.pause()
    finally:
        run(postgres + [BIN + "pg_ctl", "-D", str(data), "-m", "fast", "-w", "stop"])


if __name__ == "__main__":
    if not Path("/.dockerenv").exists() or os.geteuid() != 0 or os.environ.get("SUPIVPN_VM_DATABASE_TEST") != "1":
        raise SystemExit("Requires the disposable VM database container")
    with tempfile.TemporaryDirectory(prefix="supivpn-vm-db-") as directory:
        serve(Path(directory))
