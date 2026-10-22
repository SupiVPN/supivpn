# PostgreSQL outside the VPN VM

Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
See [LICENSE](../LICENSE) for copyright ownership and licensing terms.

The controller can use a separate PostgreSQL 18 server over verified TLS.
The VPN node and OpenVPN stay on the VPN VM and do not receive database
credentials. This separates the database's storage, backups and maintenance
from the VPN host; it does **not** make a single VPN/controller VM highly available.
See [architecture limits](../DEPLOYMENT.md#architecture-limits-to-plan-for).

**Version status:** the optional `database` setup block described below is
prepared for the next release. Published **v0.6.0** only supports a local database
through `supivpn-setup`; its controller already supports a remote database through
[manual configuration](DEPLOYMENT_MANUAL.md). Do not pass the new block to the
v0.6.0 helper. The [existing-installation procedure](#move-an-existing-database)
below also explains maintenance without the new helper.

## 1. Prepare a private database endpoint

Use a dedicated PostgreSQL **18** database on a writable primary, with a stable
DNS name such as `db.example.test`. These are examples to replace:

| Component | Private address |
| --- | --- |
| VPN/controller VM | `10.20.0.10` |
| PostgreSQL writer | `10.20.0.20:5432`, DNS `db.example.test` |

Keep these networks separate from VPN client pools. Permit TCP 5432 only from
the controller VM's private address in the database host/provider firewall.
Do not expose PostgreSQL publicly or give VPN clients a direct database route.
Use private routing between hosts; the public VPN endpoint is unrelated to the
database endpoint. For a managed service, use its writer endpoint and published
CA bundle, and verify that its administrative role can create the roles and
grants below.

For a self-managed server, install PostgreSQL 18 through the
[PostgreSQL Debian repository](https://www.postgresql.org/download/linux/debian/).
Configure its actual cluster (commonly `18/main`) with a certificate whose SAN
contains `db.example.test` and a matching private key, readable only by PostgreSQL:

```conf
listen_addresses = '10.20.0.20'
ssl = on
ssl_cert_file = '/etc/postgresql/18/main/tls/server.crt'
ssl_key_file = '/etc/postgresql/18/main/tls/server.key'
password_encryption = 'scram-sha-256'
```

Install the key as `postgres:postgres`, mode `0600`, and include necessary
intermediate certificates in the server certificate file. Obtain the public CA
through a trusted administrative channel; never copy the server private key to
the VPN VM. PostgreSQL's [`ssl = on`](https://www.postgresql.org/docs/18/ssl-tcp.html)
also permits plaintext unless client authentication rules prohibit it.

On this dedicated database server, use a narrow `pg_hba.conf` rule before any
broader network rule, retaining necessary local administrative access:

```conf
hostssl supivpn supivpn_runtime,supivpn_migrator 10.20.0.10/32 scram-sha-256
host    supivpn all                            0.0.0.0/0     reject
host    supivpn all                            ::/0          reject
```

Review the **whole** file: [the first matching rule wins](https://www.postgresql.org/docs/18/auth-pg-hba-conf.html).
Restart the cluster after changing `listen_addresses`; HBA changes need a reload.
Confirm the intended listener and firewall from both allowed and denied hosts.
TLS must validate both the CA chain and the writer hostname; do not use
`sslmode=disable`, `require` or a hostname-verification bypass for this path.

## 2. Provision an empty database and separate identities

For a **new** installation, the database administrator runs the following in
`psql` on the database server. Keep an existing database intact: these commands
are not an upgrade or data-migration script. If moving a working installation,
use the [cutover procedure](#move-an-existing-database) instead.

```sql
CREATE ROLE supivpn_owner NOLOGIN NOINHERIT;
CREATE ROLE supivpn_runtime LOGIN NOINHERIT;
CREATE ROLE supivpn_migrator LOGIN NOINHERIT;
GRANT supivpn_owner TO supivpn_migrator;
CREATE DATABASE supivpn;
REVOKE ALL ON DATABASE supivpn FROM PUBLIC;
GRANT CONNECT, CREATE ON DATABASE supivpn TO supivpn_owner;
GRANT CONNECT ON DATABASE supivpn TO supivpn_runtime, supivpn_migrator;
\connect supivpn
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT USAGE, CREATE ON SCHEMA public TO supivpn_owner;
CREATE SCHEMA supivpn AUTHORIZATION supivpn_owner;
GRANT USAGE ON SCHEMA supivpn TO supivpn_runtime;
ALTER DEFAULT PRIVILEGES FOR ROLE supivpn_owner IN SCHEMA supivpn
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO supivpn_runtime;
ALTER DEFAULT PRIVILEGES FOR ROLE supivpn_owner IN SCHEMA supivpn
  GRANT USAGE, SELECT ON SEQUENCES TO supivpn_runtime;
ALTER DEFAULT PRIVILEGES FOR ROLE supivpn_owner IN SCHEMA public
  GRANT SELECT ON TABLES TO supivpn_runtime;
\password supivpn_runtime
\password supivpn_migrator
```

Use different randomly generated passwords, entered at the hidden `\password`
prompts, and deliver them to the operator through a secure channel. Do not put
password literals in SQL history or command arguments. Neither login may be a
superuser, create roles/databases, replicate, or bypass row security. Runtime
must not be a member of the owner role. Keep these identities dedicated to
SupiVPN. The helper does not request an administrator login or create remote roles.

## 3. Configure a fresh VPN VM

Follow [DEPLOYMENT.md](../DEPLOYMENT.md) through package, certificate and IdP
preparation. Install **`postgresql-client-18` instead of `postgresql-18`** on the
VPN VM; the remote path needs `psql`, not a local PostgreSQL server.

Put the public database CA in `/root/supivpn-db-ca.pem`. Enter each database
password into a private root-owned file without echoing it or recording it in
shell history. In the root Bash session:

```bash
umask 077
set -o noclobber
read -r -s -p 'Runtime database password: ' supivpn_runtime_password
printf '\n'
printf '%s' "$supivpn_runtime_password" > /root/supivpn-db-runtime.password
unset supivpn_runtime_password
read -r -s -p 'Migration database password: ' supivpn_migration_password
printf '\n'
printf '%s' "$supivpn_migration_password" > /root/supivpn-db-migration.password
unset supivpn_migration_password
chmod 0600 /root/supivpn-db-runtime.password /root/supivpn-db-migration.password
set +o noclobber
```

Use regular files, not symlinks. Passwords must be a single nonempty line of
printable ASCII, up to 4096 bytes; one final newline in a file is accepted.
Add this **optional block** to the existing setup JSON, alongside `groups`,
`hostname`, etc. Keep only paths here, never passwords:

```json
{
  "database_name": "supivpn",
  "database": {
    "host": "db.example.test",
    "port": 5432,
    "ca_file": "/root/supivpn-db-ca.pem",
    "runtime_password_file": "/root/supivpn-db-runtime.password",
    "migration_password_file": "/root/supivpn-db-migration.password"
  }
}
```

This is a fragment, not a replacement for the full setup file. Omitting
`database` keeps local PostgreSQL setup; omitting `port` selects 5432.

```bash
supivpn-setup plan --config /root/supivpn-setup.json
supivpn-setup init --config /root/supivpn-setup.json
```

`plan` neither reads password files nor contacts the server. Before writing local
configuration, `init` checks the two logins, verified TLS, PostgreSQL 18, a writable
primary, restricted privileges and empty `public`/`supivpn` schemas. It then
copies the CA, stores separate root-only runtime/migration connection files,
runs the installed migrations and checks runtime table grants. It never creates,
starts, enables or checks a local PostgreSQL cluster in remote mode. After a
partial failure, files and remote schema are preserved for diagnosis; do not
delete them or retry blindly.

The runtime TLS block uses `verify-full` with the writer hostname and
`/etc/supivpn/controller/database-ca.pem`; the migration DSN uses the same
verified TLS settings. Treat `database.env` and `migration.env` as systemd
EnvironmentFiles, **not shell scripts**. Never `source` or print them.

Return to [configuration and service activation](../DEPLOYMENT.md#customize-the-generated-configuration).
After client acceptance, enable only `supivpn-controller` and `supivpn-node` on
the VPN VM. Arrange database startup, backups and recovery on the database host
separately. `supivpn-setup check` checks the three SupiVPN units and controller
database readiness; it does not run `systemctl` against the database server.
The input password files can be removed after secure credential retention is
arranged: maintenance uses the installed credentials, not those input files.
Track database CA/certificate expiry separately from the public VPN certificate.

## Move an existing database

Moving a running installation requires a maintenance window and a tested restore.
**Do not run `supivpn-setup init`**, start a new empty schema, or copy only selected
tables. Preserve all SupiVPN data, the `public.supivpn_schema_migrations` ledger,
object ownership, grants and default privileges. PostgreSQL roles are global
objects and [are not included in `pg_dump`](https://www.postgresql.org/docs/18/app-pgdump.html).

1. Prepare the private TLS endpoint above and an **empty destination database**.
   On it, create only the three roles, their membership, database and database
   grants from section 2; stop before `\connect` and schema creation. Set new
   login passwords. The restore supplies the schemas, owners and table grants.
   The restore administrator must be able to restore `supivpn_owner` ownership.
2. Back up `/etc/supivpn`, the wrapping key and `/var/lib/supivpn-node` securely.
   Record the installed SupiVPN versions; keep them unchanged during the move.
   Stop **every** controller/node or other SupiVPN writer using this database.
   For this combined single-VM deployment, stop the node and controller and
   verify that OpenVPN is also inactive. This disconnects clients:

   ```bash
   systemctl stop supivpn-node supivpn-controller
   systemctl is-active supivpn-node supivpn-openvpn supivpn-controller
   ```

   Each must report `inactive`; `is-active` returns nonzero for this expected
   state. Keep the source PostgreSQL running only to produce the final dump.
3. On the VPN VM, dump the complete helper-created database in the root shell.
   Replace `supivpn` if you used a different database name. Manual installs may
   use port 5432 instead of 55433:

   ```bash
   umask 077
   runuser -u postgres -- /usr/lib/postgresql/18/bin/pg_dump \
     --host=/var/run/postgresql --port=55433 --dbname=supivpn \
     --format=custom > /root/supivpn-cutover.dump
   ```

   Transfer this private dump through your approved encrypted administrator
   channel. It contains authentication/session state; do not upload it to GitHub,
   issue reports or public storage. Keep the old application writers stopped.
4. Restore on the database host into the empty `supivpn` database. For a
   self-managed host with local peer authentication, from its root shell:

   ```bash
   runuser -u postgres -- /usr/lib/postgresql/18/bin/pg_restore \
     --host=/var/run/postgresql --port=5432 --dbname=supivpn \
     --exit-on-error --single-transaction < /root/supivpn-cutover.dump
   ```

   For a managed service, use its administrative restore connection with verified
   TLS and private credentials. Do not use `--no-owner` or `--no-acl`: migrations
   check ownership and runtime relies on the grants. [`--single-transaction`](https://www.postgresql.org/docs/18/app-pgrestore.html)
   keeps a failed restore from leaving a partially restored schema. Check the
   command's exit status and compare the source/destination migration ledger and
   table counts locally without publishing their contents.
5. On the VPN VM, privately edit the two existing root-only EnvironmentFiles:
   `controller/database.env` for `supivpn_runtime`, `controller/migration.env` for
   `supivpn_migrator`. Update host, port, database and the corresponding password;
   retain `SUPIVPN_DATABASE_URL`. The migration connection must explicitly include
   `sslmode=verify-full sslrootcert=/etc/supivpn/controller/database-ca.pem`.
   Preserve correct libpq and EnvironmentFile quoting; do not paste a DSN into
   the command line or a diagnostic report. Install the public CA as
   `root:supivpn-controller`, mode `0640`, at that path and update only the
   `database_tls` object in `/etc/supivpn/controller/controller.json`:

   ```json
   {
     "mode": "verify-full",
     "ca_file": "/etc/supivpn/controller/database-ca.pem",
     "server_name": "db.example.test"
   }
   ```

   Keep credentials mode `0600`, owned by root. Do not regenerate the wrapping
   key, node journal or VPN profiles. No new schema migration is needed when
   moving the same package version and complete schema.
6. Stop and disable the **old dedicated** local cluster after the restore is
   confirmed: `systemctl disable --now postgresql@18-supivpn`. Do not stop unrelated
   clusters or remove its data. With a helper version supporting remote mode,
   add the same `database` metadata block to `/etc/supivpn/setup.json` so checks
   select remote mode; its password-input paths are not read by `check`.
   On **v0.6.0**, leave that file unchanged and use the manual checks below:
   its `check` still expects local PostgreSQL.
7. Start `supivpn-controller`, then `supivpn-node`. Verify the three SupiVPN
   units, HTTPS controller `/healthz`, node `/readyz`, a fresh profile/login,
   expected group/IP and denied resource access as in
   [deployment acceptance](../DEPLOYMENT.md#5-connect-and-finish-acceptance).
   With the new helper, run `supivpn-setup check` as well. Reboot the VPN VM in a
   maintenance window and repeat readiness/client acceptance with the old
   database still stopped. Verify automated remote backups and a restore drill.

   For manual readiness checks on v0.6.0, replace the hostname below (use the
   separate login hostname for port 8443 if configured):

   ```bash
   systemctl is-active supivpn-controller supivpn-node supivpn-openvpn
   curl --fail --silent --show-error --noproxy '*' \
     --resolve vpn.example.test:8443:127.0.0.1 https://vpn.example.test:8443/healthz
   curl --fail --silent --show-error --noproxy '*' \
     --resolve vpn.example.test:9443:127.0.0.1 https://vpn.example.test:9443/readyz
   ```

Keep only one authoritative database writable by the application. Before any
new application writes on the destination, an aborted cutover can return to the
unchanged source and its saved configuration. **After new writes, the old dump or
source is stale**: switching back can resurrect authorization/replay state or
rewind fencing generations. Stop and follow [recovery guidance](RECOVERY.md)
instead of rolling back a database snapshot. Do not remove the source backup
until the destination and its recovery procedure have been validated.
