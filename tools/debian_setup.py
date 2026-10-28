#!/usr/bin/python3
# Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
# SPDX-License-Identifier: AGPL-3.0-only
"""Explicit first-time setup for the combined Debian package; never a postinst."""
import argparse
import ipaddress
import json
import math
import os
from pathlib import Path
import pwd
import re
import secrets
import socket
import stat
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET

ROOT = Path("/etc/supivpn")
PG = Path("/etc/postgresql/18/supivpn")
PORT = 55433
ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8"}
EXAMPLES = Path("/usr/share/supivpn/examples")
PSQL = "/usr/lib/postgresql/18/bin/psql"


class SetupError(Exception):
    pass


def run(args, *, data=None, env=None):
    # Never include arguments, SQL, output or credentials in an exception/log.
    try:
        result = subprocess.run(args, input=data, capture_output=True, timeout=180,
                                env=ENV | (env or {}))
    except (OSError, subprocess.TimeoutExpired):
        raise SetupError(f"{Path(args[0]).name} could not complete; output withheld") from None
    if result.returncode:
        raise SetupError(f"{Path(args[0]).name} failed; output withheld")
    return result.stdout


def read(path, limit=2 * 1024 * 1024):
    # Source symlinks are needed for Certbot, but devices/FIFOs must not block.
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise SetupError("Input must be a regular file")
        content = stream.read(limit + 1)
    if len(content) > limit:
        raise SetupError("Input file exceeds the size limit")
    return content


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise SetupError("Duplicate configuration field")
        result[key] = value
    return result


def valid_hostname(value):
    return isinstance(value, str) and len(value) <= 253 and all(
        re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
        for label in value.split("."))


def absolute_path(value):
    return isinstance(value, str) and value.startswith("/") and not any(
        ord(char) < 32 for char in value) and ".." not in Path(value).parts


def configuration(path):
    c = json.loads(read(path, 16384), object_pairs_hook=unique_object)
    allowed = {"hostname", "login_hostname", "certificate_directory", "idp_metadata_file",
               "groups", "vpn_network", "admin_cidr", "ssh_port", "database_name", "database", "tcp_fallback"}
    if not isinstance(c, dict) or set(c) - allowed:
        raise SetupError("Unknown setup fields; see the packaged setup example")
    c.setdefault("login_hostname", c.get("hostname"))
    c.setdefault("vpn_network", "10.203.0.0/24")
    c.setdefault("ssh_port", 22)
    c.setdefault("database_name", "supivpn")
    for key in ("hostname", "login_hostname"):
        value = c.get(key)
        if not valid_hostname(value):
            raise SetupError("Hostnames must be lowercase DNS names, without a port or URL")
    for key in ("certificate_directory", "idp_metadata_file"):
        value = c.get(key)
        if not absolute_path(value):
            raise SetupError("Certificate directory and metadata file must be absolute paths")
    groups = c.get("groups")
    if not isinstance(groups, list) or not 1 <= len(groups) <= 16 or any(
            not isinstance(g, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.@ -]{0,127}", g)
            or g != g.strip() for g in groups) or len(set(groups)) != len(groups):
        raise SetupError("Provide 1 to 16 distinct IdP group names, in priority order")
    network = ipaddress.IPv4Network(c["vpn_network"])
    private = any(network.subnet_of(ipaddress.IPv4Network(block)) for block in
                  ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))
    if not private or not 16 <= network.prefixlen <= 26:
        raise SetupError("VPN network must be a private IPv4 /16 to /26")
    if network.prefixlen + math.ceil(math.log2(len(groups))) > 28:
        raise SetupError("VPN network is too small for these groups")
    admin = ipaddress.IPv4Network(c.get("admin_cidr", ""))
    if admin.prefixlen < 16 or admin.overlaps(network):
        raise SetupError("Use a specific administration IPv4 CIDR outside the VPN network")
    if type(c["ssh_port"]) is not int or not 1 <= c["ssh_port"] <= 65535:
        raise SetupError("SSH port must be between 1 and 65535")
    if c["ssh_port"] in (80, 8443, 9443, PORT):
        raise SetupError("SSH port conflicts with a SupiVPN or database port")
    if "tcp_fallback" in c:
        tcp = c["tcp_fallback"]
        if not isinstance(tcp, dict) or set(tcp) - {"enabled", "port"}:
            raise SetupError("TCP fallback accepts enabled and port; it shares the configured VPN network")
        tcp.setdefault("enabled", False)
        if type(tcp["enabled"]) is not bool:
            raise SetupError("TCP fallback enabled must be true or false")
        tcp.setdefault("port", 443)
        if type(tcp["port"]) is not int or not 1 <= tcp["port"] <= 65535:
            raise SetupError("TCP fallback port must be between 1 and 65535")
        if tcp["enabled"] and tcp["port"] in (80, 8443, 9443, PORT, c["ssh_port"]):
            raise SetupError("TCP fallback port must be unused and must not conflict with another service")
        if not tcp["enabled"]:
            del c["tcp_fallback"]
    if not isinstance(c["database_name"], str) or not re.fullmatch(r"[a-z][a-z0-9_]{0,62}", c["database_name"]):
        raise SetupError("Invalid database name")
    if c["database_name"] in {"postgres", "template0", "template1"}:
        raise SetupError("Database name is reserved")
    if "database" in c:
        db = c["database"]
        required = {"host", "ca_file", "runtime_password_file", "migration_password_file"}
        if not isinstance(db, dict) or not required <= db.keys() or db.keys() - required - {"port"}:
            raise SetupError("Remote database requires host, ca_file and separate password files")
        db.setdefault("port", 5432)
        if not valid_hostname(db["host"]) or type(db["port"]) is not int or not 1 <= db["port"] <= 65535:
            raise SetupError("Use a database hostname and a TCP port from 1 to 65535")
        if any(not absolute_path(db[key]) for key in required - {"host"}):
            raise SetupError("Remote database input files must use absolute paths")
    c["vpn_network"], c["admin_cidr"] = str(network), str(admin)
    return c


def configs(c, uid):
    agent = json.loads(read(EXAMPLES / "agent.example.json"))
    controller = json.loads(read(EXAMPLES / "controller.example.json"))
    network = ipaddress.IPv4Network(c["vpn_network"])
    pools = list(network.subnets(prefixlen_diff=math.ceil(math.log2(len(c["groups"])))))
    groups = [{"name": name, "priority": (i + 1) * 10} for i, name in enumerate(c["groups"])]
    controller["groups"] = groups
    controller["public_url"] = "https://" + c["login_hostname"] + ":8443"
    controller["profile"]["endpoint"] = c["hostname"]
    if "tcp_fallback" in c:
        controller["profile"]["tcp_fallback_port"] = c["tcp_fallback"]["port"]
    controller["database_tls"] = {
        "mode": "verify-full", "ca_file": str(ROOT / "controller/database-ca.pem"),
        "server_name": c["database"]["host"] if "database" in c else "127.0.0.1",
    }
    agent["public_url"] = "https://" + c["hostname"] + ":9443"
    agent["vpn_network"] = str(network)
    agent["group_pools"] = [{"group_name": g["name"], "priority": g["priority"], "cidr": str(pool)}
                            for g, pool in zip(groups, pools)]
    if "tcp_fallback" in c:
        agent["tcp_management_socket"] = "/run/supivpn/management-tcp.sock"
    agent["remote_controller"]["controller_uid"] = uid
    agent["remote_controller"]["public_url"] = controller["public_url"]
    server = read(EXAMPLES / "server.conf.example").decode()
    server = server.replace("server 10.203.0.0 255.255.255.0 nopool",
                            f"server {network.network_address} {network.netmask} nopool")
    if "tcp_fallback" in c:
        route_args = f"-route-device supivpn0 -route-network {network}"
        server = server.replace('-learn-address"', f'-learn-address {route_args}"')
        server += f'client-disconnect "/usr/sbin/supivpn -route-disconnect {route_args}"\n'
    return agent, controller, server


def tcp_server_config(c, server):
    """Both transports use the same pool; per-client /32 routes select their TUN."""
    server = server.replace("port 1194\n", f"port {c['tcp_fallback']['port']}\n")
    server = server.replace("proto udp4\n", "proto tcp4-server\n").replace("supivpn0", "supivpn1")
    return server.replace("/run/supivpn/management.sock", "/run/supivpn/management-tcp.sock")


def service_units(c):
    units = ["supivpn-controller", "supivpn-node", "supivpn-openvpn"]
    if "tcp_fallback" in c:
        units += ["supivpn-openvpn-tcp"]
    return units


def firewall(c):
    gateway = ipaddress.IPv4Network(c["vpn_network"])[1]
    tcp_input = tcp_port = ""
    if "tcp_fallback" in c:
        network = ipaddress.IPv4Network(c["vpn_network"])
        tcp_input = f'    iifname "supivpn1" ip saddr {network} ip daddr {network[1]} icmp type echo-request accept\n    iifname "supivpn1" drop\n'
        tcp_port = f"    tcp dport {c['tcp_fallback']['port']} accept\n"
    return f"""#!/usr/sbin/nft -f
# Fresh dedicated host only: review before replacing the existing ruleset.
flush ruleset
table inet supivpn {{
  chain input {{
    type filter hook input priority 0; policy drop;
    iifname "lo" accept
    ct state invalid drop
    iifname "supivpn0" ip saddr {c['vpn_network']} ip daddr {gateway} icmp type echo-request accept
    iifname "supivpn0" drop
{tcp_input}    ct state established,related accept
    ip saddr {c['admin_cidr']} tcp dport {c['ssh_port']} accept
    tcp dport {{ 80, 8443 }} accept
    udp dport 1194 accept
{tcp_port}    ip protocol icmp accept
    meta l4proto ipv6-icmp accept
    udp sport 67 udp dport 68 accept
    udp sport 547 udp dport 546 accept
  }}
  chain forward {{
    type filter hook forward priority 0; policy drop;
  }}
  chain output {{
    type filter hook output priority 0; policy accept;
  }}
}}
"""


def write(path, content, mode=0o600, uid=0, gid=0, replace=False):
    # Parent directories are created privately by this tool. Refuse links and
    # accidental overwrites; certificate refresh explicitly permits replacement.
    if path.is_symlink() or (path.exists() and not replace):
        raise SetupError("Refusing an existing output file")
    if isinstance(content, str):
        content = content.encode()
    fd, name = tempfile.mkstemp(prefix=".setup-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            os.fchmod(stream.fileno(), mode)
            os.fchown(stream.fileno(), uid, gid)
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def directory(path, mode, uid=0, gid=0):
    path.mkdir(mode=mode)
    os.chown(path, uid, gid)
    path.chmod(mode)


def certificate_inputs(c):
    # Copy once to private scratch space, validate those exact bytes, then
    # install. Certbot's live symlinks are supported, including on renewal.
    source = Path(c["certificate_directory"])
    values = {name: read(source / src) for name, src in
              (("crt.pem", "cert.pem"), ("chain.pem", "chain.pem"), ("key.pem", "privkey.pem"))}
    template = read(EXAMPLES / "client.ovpn.example")
    match = re.search(rb"<ca>\s*(.*?)\s*</ca>", template, re.S)
    if not match:
        raise SetupError("Packaged client template has no CA")
    with tempfile.TemporaryDirectory(prefix="supivpn-certificate-") as tmp:
        folder = Path(tmp)
        for name, data in values.items():
            write(folder / name, data)
        write(folder / "ca.pem", match[1] + b"\n")
        cert = str(folder / "crt.pem")
        for hostname in {c["hostname"], c["login_hostname"]}:
            run(["openssl", "verify", "-purpose", "sslserver", "-verify_hostname", hostname,
                 "-no-CApath", "-no-CAstore", "-CAfile", str(folder / "ca.pem"),
                 "-untrusted", str(folder / "chain.pem"), cert])
        run(["openssl", "x509", "-in", cert, "-checkend", "86400", "-noout"])
        public = run(["openssl", "x509", "-in", cert, "-pubkey", "-noout"])
        key_public = run(["openssl", "pkey", "-in", str(folder / "key.pem"),
                          "-passin", "pass:", "-pubout"])
        if public != key_public:
            raise SetupError("Certificate and private key do not match")
    return values, template


def install_certificates(values, gid, replace=False):
    for name, content in values.items():
        write(ROOT / "node" / name, content, replace=replace)
        write(ROOT / "controller" / name, content, 0o640, gid=gid, replace=replace)


def preflight(c=None):
    remote = c is not None and "database" in c
    if os.geteuid() != 0 or not sys.platform.startswith("linux"):
        raise SetupError("Run setup as root on Debian 13")
    if not read("/etc/debian_version", 128).startswith(b"13.") or read("/proc/1/comm", 128).strip() != b"systemd":
        raise SetupError("Debian 13 with systemd as PID 1 is required")
    paths = [ROOT, Path("/var/lib/supivpn-node")]
    if not remote:
        paths += [PG, Path("/var/lib/postgresql/18/supivpn")]
    for path in paths:
        if path.exists() or path.is_symlink():
            raise SetupError("Existing SupiVPN configuration, database or state found; init never overwrites it")
    versions = run(["dpkg-query", "-W", "-f=${Status} ${Version}\n", "supivpn", "supivpn-node", "supivpn-controller"]).decode().splitlines()
    if len(versions) != 3 or len(set(versions)) != 1 or not versions[0].startswith("install ok installed "):
        raise SetupError("Install matching versions of all three SupiVPN packages")
    if not run(["/usr/sbin/openvpn", "--version"]).startswith(b"OpenVPN 2.7.8 "):
        raise SetupError("OpenVPN 2.7.8 is required by this package version")
    if remote:
        if not Path(PSQL).is_file():
            raise SetupError("Install postgresql-client-18 for remote database setup")
    elif not Path("/usr/lib/postgresql/18/bin/initdb").is_file():
        raise SetupError("Install postgresql-18 before setup")
    if not stat.S_ISCHR(Path("/dev/net/tun").stat().st_mode):
        raise SetupError("The VM must provide /dev/net/tun")
    ports = [("0.0.0.0", 8443), ("127.0.0.1", 9443)]
    if c is not None and "tcp_fallback" in c:
        ports.append(("0.0.0.0", c["tcp_fallback"]["port"]))
    if not remote:
        ports.append(("127.0.0.1", PORT))
    for address, port in ports:
        with socket.socket() as sock:
            try:
                sock.bind((address, port))
            except OSError:
                raise SetupError("A required TCP port is already in use") from None
    with socket.socket(type=socket.SOCK_DGRAM) as sock:
        try:
            sock.bind(("0.0.0.0", 1194))
        except OSError:
            raise SetupError("OpenVPN UDP port 1194 is already in use") from None
    user = pwd.getpwnam("supivpn-controller")
    if not 0 < user.pw_uid < 1000 or user.pw_dir != "/nonexistent" or user.pw_shell != "/usr/sbin/nologin":
        raise SetupError("Invalid controller service account")
    return user


def password_input(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        # init has already required root. Never follow links or consume an input
        # writable/readable by another user, a device, or a potentially blocking FIFO.
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise SetupError("Database password files must be private regular files owned by root")
        value = stream.read(4098)
    if value.endswith(b"\n"):
        value = value[:-1]
    if not 1 <= len(value) <= 4096 or any(byte < 32 or byte > 126 for byte in value):
        raise SetupError("Database passwords must be one nonempty line of printable ASCII")
    return value.decode("ascii")


def remote_inputs(c):
    db = c["database"]
    result = {"ca": read(db["ca_file"]),
              "runtime": password_input(db["runtime_password_file"]),
              "migrator": password_input(db["migration_password_file"])}
    if b"PRIVATE KEY" in result["ca"]:
        raise SetupError("The database CA file must contain public certificates only")
    if result["runtime"] == result["migrator"]:
        raise SetupError("Use different runtime and migration passwords")
    return result


def remote_query(c, credentials, role, query, ca_file=None):
    db = c["database"]
    return run([PSQL, "-X", "-w", "-A", "-t", "-v", "ON_ERROR_STOP=1", "-c", query], env={
        "PGHOST": db["host"], "PGPORT": str(db["port"]), "PGDATABASE": c["database_name"],
        "PGUSER": "supivpn_" + role, "PGPASSWORD": credentials[role],
        "PGSSLMODE": "verify-full", "PGSSLROOTCERT": str(ca_file or db["ca_file"]),
        "PGCONNECT_TIMEOUT": "5", "PGOPTIONS": "-c statement_timeout=5000 -c lock_timeout=2000",
    }).strip()


def verify_remote_database(c, credentials):
    # Read-only probes before any host writes or migrations. A remote init is
    # only for a dedicated, pre-provisioned empty database, not an existing cluster.
    common = """SELECT current_setting('server_version_num')::int BETWEEN 180000 AND 189999
AND NOT pg_is_in_recovery() AND current_setting('transaction_read_only') = 'off'
AND NOT (rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls)
"""
    runtime = common + """AND NOT pg_has_role(current_user, 'supivpn_owner', 'MEMBER')
AND NOT has_database_privilege(current_user, current_database(), 'CREATE')
AND NOT has_database_privilege(current_user, current_database(), 'TEMP')
AND has_schema_privilege(current_user, 'supivpn', 'USAGE')
AND NOT has_schema_privilege(current_user, 'supivpn', 'CREATE')
AND NOT has_schema_privilege(current_user, 'public', 'CREATE')
FROM pg_roles WHERE rolname = current_user"""
    migrator = common + """AND pg_has_role(current_user, 'supivpn_owner', 'SET')
AND EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'supivpn_owner'
            AND NOT (rolcanlogin OR rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls))
AND EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = 'supivpn' AND nspowner = 'supivpn_owner'::regrole)
AND NOT EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
                WHERE n.nspname IN ('supivpn', 'public'))
AND NOT EXISTS (SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
                WHERE n.nspname IN ('supivpn', 'public'))
FROM pg_roles WHERE rolname = current_user"""
    for role, query in (("runtime", runtime), ("migrator", migrator)):
        if remote_query(c, credentials, role, query) != b"t":
            raise SetupError("Remote database must be an empty PostgreSQL 18 writer with the documented restricted roles")


def connection_string(c, role, password, *, tls=False):
    values = {"host": c["database"]["host"], "port": str(c["database"]["port"]),
              "dbname": c["database_name"], "user": "supivpn_" + role, "password": password}
    if tls:
        values |= {"sslmode": "verify-full", "sslrootcert": str(ROOT / "controller/database-ca.pem")}
    # libpq/pgx keyword syntax, then separately quote the EnvironmentFile value.
    return " ".join(key + "='" + value.replace("\\", "\\\\").replace("'", "\\'") + "'"
                    for key, value in values.items())


def remote_database(c, gid, credentials):
    ca = ROOT / "controller/database-ca.pem"
    write(ca, credentials["ca"], 0o640, gid=gid)
    runtime = connection_string(c, "runtime", credentials["runtime"])
    migrator = connection_string(c, "migrator", credentials["migrator"], tls=True)
    for name, dsn in (("database.env", runtime), ("migration.env", migrator)):
        write(ROOT / "controller" / name, "SUPIVPN_DATABASE_URL=" + json.dumps(dsn) + "\n")
    run(["/usr/sbin/supivpn-migrate"], env={"SUPIVPN_DATABASE_URL": migrator})
    # Check actual grants after DDL, not just defaults on an empty schema.
    query = """SELECT has_table_privilege(current_user, 'public.supivpn_schema_migrations', 'SELECT')
AND NOT EXISTS (
 SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
 CROSS JOIN unnest(ARRAY['SELECT','INSERT','UPDATE','DELETE']) AS p(privilege)
 WHERE n.nspname = 'supivpn' AND c.relkind IN ('r','p')
 AND NOT has_table_privilege(current_user, c.oid, p.privilege))"""
    if remote_query(c, credentials, "runtime", query, ca) != b"t":
        raise SetupError("Remote runtime grants are incomplete after migration; inspect the preserved setup")


def database(c, gid):
    run(["pg_createcluster", "--start-conf=manual", "--port=" + str(PORT),
         "--locale=C.UTF-8", "18", "supivpn",
         "--", "--auth-local=peer", "--auth-host=scram-sha-256"])
    pg = pwd.getpwnam("postgres")
    directory(PG / "supivpn-tls", 0o700, pg.pw_uid, pg.pw_gid)
    run(["openssl", "req", "-x509", "-newkey", "rsa:3072", "-nodes", "-days", "365",
         "-subj", "/CN=localhost", "-addext", "subjectAltName=IP:127.0.0.1,DNS:localhost",
         "-addext", "extendedKeyUsage=serverAuth", "-keyout", str(PG / "supivpn-tls/server.key"),
         "-out", str(PG / "supivpn-tls/server.crt")])
    for name in ("server.key", "server.crt"):
        path = PG / "supivpn-tls" / name
        os.chown(path, pg.pw_uid, pg.pw_gid)
        path.chmod(0o600)
    write(ROOT / "controller/database-ca.pem", read(PG / "supivpn-tls/server.crt"), 0o640, gid=gid)
    write(PG / "conf.d/supivpn.conf", "listen_addresses = '127.0.0.1'\nssl = on\nssl_cert_file = '" + str(PG / "supivpn-tls/server.crt") +
          "'\nssl_key_file = '" + str(PG / "supivpn-tls/server.key") + "'\npassword_encryption = 'scram-sha-256'\n", 0o644)
    db = c["database_name"]  # Strict identifier validation precedes any SQL.
    write(PG / "pg_hba.conf", "local all postgres peer\n" +
          f"hostssl {db} supivpn_runtime,supivpn_migrator 127.0.0.1/32 scram-sha-256\n",
          0o640, pg.pw_uid, pg.pw_gid, replace=True)
    run(["systemctl", "daemon-reload"])
    run(["systemctl", "start", "postgresql@18-supivpn"])
    runtime, migrator = secrets.token_hex(32), secrets.token_hex(32)
    sql = f"""SET log_statement = 'none';
SET log_min_error_statement = 'panic';
CREATE ROLE supivpn_owner NOLOGIN NOINHERIT;
CREATE ROLE supivpn_runtime LOGIN NOINHERIT PASSWORD '{runtime}';
CREATE ROLE supivpn_migrator LOGIN NOINHERIT PASSWORD '{migrator}';
GRANT supivpn_owner TO supivpn_migrator;
CREATE DATABASE {db};
REVOKE ALL ON DATABASE {db} FROM PUBLIC;
GRANT CONNECT, CREATE ON DATABASE {db} TO supivpn_owner;
GRANT CONNECT ON DATABASE {db} TO supivpn_runtime, supivpn_migrator;
\\connect {db}
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT USAGE, CREATE ON SCHEMA public TO supivpn_owner;
CREATE SCHEMA supivpn AUTHORIZATION supivpn_owner;
GRANT USAGE ON SCHEMA supivpn TO supivpn_runtime;
ALTER DEFAULT PRIVILEGES FOR ROLE supivpn_owner IN SCHEMA supivpn GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO supivpn_runtime;
ALTER DEFAULT PRIVILEGES FOR ROLE supivpn_owner IN SCHEMA supivpn GRANT USAGE, SELECT ON SEQUENCES TO supivpn_runtime;
ALTER DEFAULT PRIVILEGES FOR ROLE supivpn_owner IN SCHEMA public GRANT SELECT ON TABLES TO supivpn_runtime;
"""
    psql = ["runuser", "-u", "postgres", "--", "psql", "-X", "-h", "/var/run/postgresql",
            "-p", str(PORT), "-d", "postgres", "-v", "ON_ERROR_STOP=1"]
    run(psql, data=sql.encode())
    base = f"host=127.0.0.1 port={PORT} dbname={db}"
    tls = " sslmode=verify-full sslrootcert=/etc/supivpn/controller/database-ca.pem"
    migration_dsn = base + " user=supivpn_migrator password=" + migrator + tls
    # Persist only root-readable credentials for explicit future migrations.
    write(ROOT / "controller/migration.env", "SUPIVPN_DATABASE_URL=\"" + migration_dsn + "\"\n")
    write(ROOT / "controller/database.env", "SUPIVPN_DATABASE_URL=\"" + base +
          " user=supivpn_runtime password=" + runtime + "\"\n")
    run(["/usr/sbin/supivpn-migrate"], env={"SUPIVPN_DATABASE_URL": migration_dsn})


def initialize(c):
    user = preflight(c)
    values, template = certificate_inputs(c)
    metadata = read(c["idp_metadata_file"])
    # Parse only public metadata, without external entity expansion/downloads.
    if b"<!DOCTYPE" in metadata or b"<!ENTITY" in metadata:
        raise SetupError("IdP metadata must not contain a DTD or entities")
    document = ET.fromstring(metadata)
    if document.tag != "{urn:oasis:names:tc:SAML:2.0:metadata}EntityDescriptor" or not document.get("entityID"):
        raise SetupError("Expected one SAML EntityDescriptor from the IdP")
    remote = remote_inputs(c) if "database" in c else None
    if remote is not None:
        verify_remote_database(c, remote)
    agent, controller, server = configs(c, user.pw_uid)
    os.umask(0o077)
    directory(ROOT, 0o755)
    write(ROOT / "setup.json", json.dumps(c, indent=2) + "\n")
    print("Preparing configuration and wrapping key", flush=True)
    directory(ROOT / "node", 0o700)
    directory(ROOT / "controller", 0o750, gid=user.pw_gid)
    directory(ROOT / "keys", 0o700)
    install_certificates(values, user.pw_gid)
    write(ROOT / "node/idp-metadata.xml", metadata)
    write(ROOT / "controller/idp-metadata.xml", metadata, 0o640, gid=user.pw_gid)
    write(ROOT / "node/agent.json", json.dumps(agent, indent=2) + "\n")
    write(ROOT / "controller/controller.json", json.dumps(controller, indent=2) + "\n", 0o640, gid=user.pw_gid)
    write(ROOT / "controller/client.ovpn.template", template, 0o640, gid=user.pw_gid)
    write(ROOT / "node/openvpn.conf", server)
    if "tcp_fallback" in c:
        write(ROOT / "node/openvpn-tcp.conf", tcp_server_config(c, server))
    write(ROOT / "firewall.nft", firewall(c))
    run(["/usr/sbin/supivpn-profile", "-init", "-server-key", str(ROOT / "keys/tls-crypt-v2-server.key")])
    os.chown(ROOT / "keys/tls-crypt-v2-server.key", user.pw_uid, user.pw_gid)
    (ROOT / "keys/tls-crypt-v2-server.key").chmod(0o600)
    os.chown(ROOT / "keys", 0, user.pw_gid)
    (ROOT / "keys").chmod(0o750)
    run(["/usr/sbin/supivpn", "-config", str(ROOT / "node/agent.json"), "-check-config"])
    if remote is not None:
        print("Configuring the remote PostgreSQL writer and applying migrations", flush=True)
        remote_database(c, user.pw_gid, remote)
    else:
        print("Creating dedicated PostgreSQL 18/supivpn and applying migrations", flush=True)
        database(c, user.pw_gid)
    run(["systemd-analyze", "verify"] + [unit + ".service" for unit in service_units(c)])
    write(ROOT / "setup-complete", "Setup completed; services remain stopped.\n")
    print("Setup complete. Review /etc/supivpn/firewall.nft, then follow DEPLOYMENT.md to start and check services.")


def check(c):
    units = service_units(c)
    if "database" not in c:
        units.insert(0, "postgresql@18-supivpn")
    for unit in units:
        run(["systemctl", "is-active", "--quiet", unit])
        print(unit + ": active")
    for hostname, port, endpoint in ((c["login_hostname"], 8443, "healthz"), (c["hostname"], 9443, "readyz")):
        run(["curl", "--fail", "--silent", "--show-error", "--noproxy", "*", "--connect-timeout", "5", "--max-time", "10",
             "--resolve", f"{hostname}:{port}:127.0.0.1", f"https://{hostname}:{port}/{endpoint}"])
        print(endpoint + ": ready (TLS verified)")
    if "database" in c:
        print("Remote PostgreSQL: controller database readiness passed")
    print("Next: verify a real IdP login, client tunnel and denied access; health alone is not VPN acceptance.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["plan", "init", "check", "certificates"])
    parser.add_argument("--config", default=str(ROOT / "setup.json"))
    args = parser.parse_args()
    try:
        c = configuration(args.config)
        if args.action == "plan":
            print("Create /etc/supivpn; configure one controller and node; generate wrapping key.")
            print("All profiles require verified SAML ownership. UDP/1194 is primary.")
            if "tcp_fallback" in c:
                print(f"Add TCP/{c['tcp_fallback']['port']} fallback; one agent manages two daemons within the configured VPN network.")
                print("The node service starts both OpenVPN transports; no second agent or node identity.")
            if "database" in c:
                print("Use the pre-provisioned remote PostgreSQL 18 writer; verify TLS and restricted roles, apply migrations.")
                print("No local database cluster will be created, started or checked.")
            else:
                print(f"Create PostgreSQL 18/supivpn on 127.0.0.1:{PORT}; restricted roles, TLS, migrations.")
            print("Existing SupiVPN state is refused. Firewall is written for review, never applied.")
            print("No downloads, APT changes, service enablement or VPN start.")
            if "database" not in c:
                print("Init starts only its new local database.")
            print("ACS: https://" + c["login_hostname"] + ":8443/saml/acs")
            print("Entity ID: https://" + c["login_hostname"] + ":8443/saml/metadata")
            print("Groups (priority order): " + ", ".join(c["groups"]))
        elif args.action == "init":
            initialize(c)
        else:
            if os.geteuid() != 0 or not (ROOT / "setup-complete").is_file():
                raise SetupError("A completed setup and root access are required")
            if c != configuration(ROOT / "setup.json"):
                raise SetupError("Use the saved setup configuration for maintenance")
            if args.action == "check":
                check(c)
            else:
                # Stop first so no process can observe a partially replaced pair.
                for unit in service_units(c):
                    if run(["systemctl", "show", "--property=ActiveState", "--value", unit]).strip() not in (b"inactive", b"failed"):
                        raise SetupError("Stop the controller and node before refreshing certificate copies")
                values, _ = certificate_inputs(c)
                install_certificates(values, pwd.getpwnam("supivpn-controller").pw_gid, replace=True)
                print("Certificate copies refreshed. Start services and run supivpn-setup check.")
        return 0
    except (OSError, ValueError, KeyError, TypeError, ET.ParseError, SetupError) as exc:
        message = str(exc) if isinstance(exc, SetupError) else "Invalid or unavailable setup input; details withheld"
        print("Setup failed: " + message, file=sys.stderr)
        print("Existing files and keys were not removed. After a partial init, inspect locally; do not delete state or rerun blindly.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
