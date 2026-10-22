# Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
# SPDX-License-Identifier: AGPL-3.0-only
"""Real TLS/role/migration checks in the isolated, disposable PostgreSQL image."""
import ctypes
import importlib.util
import json
import os
from pathlib import Path
import pwd
import tempfile

spec = importlib.util.spec_from_file_location("setup", "/test/debian_setup.py")
setup = importlib.util.module_from_spec(spec)
spec.loader.exec_module(setup)
BIN = "/usr/lib/postgresql/18/bin/"


def rejected(action):
    try:
        action()
    except setup.SetupError:
        return
    raise AssertionError("Unsafe remote database was accepted")


def check(root):
    pg = pwd.getpwnam("postgres")
    root.chmod(0o755)
    data = root / "data"
    data.mkdir(mode=0o700)
    os.chown(data, pg.pw_uid, pg.pw_gid)

    def postgres(*args):
        return setup.run(["runuser", "-u", "postgres", "--", *args])

    postgres(BIN + "initdb", "-D", str(data), "--auth-local=trust", "--auth-host=scram-sha-256")
    cert, key = data / "server.crt", data / "server.key"
    setup.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
               "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost",
               "-keyout", str(key), "-out", str(cert)])
    key.chmod(0o600)
    os.chown(key, pg.pw_uid, pg.pw_gid)
    (data / "pg_hba.conf").write_text(
        "local all all trust\nhostssl supivpn_test all 127.0.0.1/32 scram-sha-256\n")
    with (data / "postgresql.conf").open("a") as stream:
        stream.write("\nlisten_addresses='127.0.0.1'\nssl=on\n"
                     "ssl_cert_file='server.crt'\nssl_key_file='server.key'\n"
                     "log_statement='none'\nlog_min_error_statement='panic'\n")
    postgres(BIN + "pg_ctl", "-D", str(data), "-l", str(data / "server.log"), "-w", "start")
    try:
        postgres(BIN + "createdb", "-h", "/var/run/postgresql", "supivpn_test")

        def sql(query):
            return postgres(BIN + "psql", "-X", "-w", "-h", "/var/run/postgresql", "-d", "supivpn_test",
                            "-v", "ON_ERROR_STOP=1", "-Atc", query).strip()

        sql("""CREATE ROLE supivpn_owner NOLOGIN NOINHERIT;
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
        # Per-run synthetic passwords include characters needing DSN and systemd
        # quoting. Pass DDL on stdin; never emit credentials in arguments/logs.
        passwords = {role: os.urandom(24).hex() + " ' \\ \" $" for role in ("runtime", "migrator")}
        for role, value in passwords.items():
            setup.run(["runuser", "-u", "postgres", "--", BIN + "psql", "-X", "-w", "-h",
                       "/var/run/postgresql", "-d", "supivpn_test", "-v", "ON_ERROR_STOP=1"],
                      data=("ALTER ROLE supivpn_" + role + " PASSWORD '" + value.replace("'", "''") + "';").encode())
        setup.ROOT = root / "installed"
        (setup.ROOT / "controller").mkdir(parents=True)
        c = {"database_name": "supivpn_test", "database": {"host": "localhost", "port": 5432, "ca_file": str(cert)}}
        credentials = passwords | {"ca": cert.read_bytes()}
        setup.verify_remote_database(c, credentials)
        c["database"]["host"] = "127.0.0.1"  # Certificate has only DNS:localhost.
        rejected(lambda: setup.verify_remote_database(c, credentials))
        c["database"]["host"] = "localhost"
        c["database"]["ca_file"] = "/etc/ssl/certs/ca-certificates.crt"
        rejected(lambda: setup.verify_remote_database(c, credentials))
        c["database"]["ca_file"] = str(cert)
        rejected(lambda: setup.verify_remote_database(c, credentials | {"runtime": "wrong"}))
        sql("GRANT CREATE ON SCHEMA supivpn TO supivpn_runtime")
        rejected(lambda: setup.verify_remote_database(c, credentials))
        sql("REVOKE CREATE ON SCHEMA supivpn FROM supivpn_runtime")
        sql("CREATE TABLE public.sentinel (value int)")
        rejected(lambda: setup.verify_remote_database(c, credentials))
        sql("DROP TABLE public.sentinel")
        sql("ALTER ROLE supivpn_migrator SET default_transaction_read_only = on")
        rejected(lambda: setup.verify_remote_database(c, credentials))
        sql("ALTER ROLE supivpn_migrator RESET default_transaction_read_only")
        setup.verify_remote_database(c, credentials)
        setup.remote_database(c, os.getgid(), credentials)
        assert int(sql("SELECT max(version) FROM public.supivpn_schema_migrations")) > 0
        assert sql("SELECT count(*) FROM pg_tables WHERE schemaname='supivpn'") != b"0"
        rejected(lambda: setup.verify_remote_database(c, credentials))
        # Parse the file's JSON-compatible quoted value, then let real libpq
        # check DSN escaping without putting a password in process arguments.
        # This does not exercise the systemd EnvironmentFile parser.
        pq = ctypes.CDLL("libpq.so.5")
        pq.PQconnectdb.argtypes, pq.PQconnectdb.restype = [ctypes.c_char_p], ctypes.c_void_p
        pq.PQstatus.argtypes, pq.PQstatus.restype = [ctypes.c_void_p], ctypes.c_int
        pq.PQfinish.argtypes = [ctypes.c_void_p]
        for filename in ("database.env", "migration.env"):
            path = setup.ROOT / "controller" / filename
            assert path.stat().st_mode & 0o777 == 0o600
            dsn = json.loads(path.read_text().split("=", 1)[1])
            dsn += " sslmode=verify-full sslrootcert='" + str(cert) + "'"
            connection = pq.PQconnectdb(dsn.encode())
            try:
                assert connection and pq.PQstatus(connection) == 0, "Stored DSN could not authenticate"
            finally:
                pq.PQfinish(connection)
        print("Remote setup: TLS, hostname/CA/password rejection, role/empty/writer checks, migrations and DSN escaping passed")
    finally:
        postgres(BIN + "pg_ctl", "-D", str(data), "-m", "immediate", "-w", "stop")


if __name__ == "__main__":
    if not Path("/.dockerenv").exists() or os.geteuid() != 0 or os.environ.get("SUPIVPN_SETUP_DB_TEST") != "1":
        raise SystemExit("Requires the disposable setup database test container")
    with tempfile.TemporaryDirectory(prefix="supivpn-remote-db-") as directory:
        check(Path(directory))
