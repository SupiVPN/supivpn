# PostgreSQL for SupiVPN

Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
See [LICENSE](../LICENSE) for copyright ownership and licensing terms.

The controller uses PostgreSQL 18, either self-managed or a managed service such
as RDS. Instance classes, networks, DNS, storage, backup retention, and failover
policies are deployment choices. Agents do not need database credentials.

## Roles and ownership

| Role | Permissions |
| --- | --- |
| Deployment administrator | Create the database, roles, and grants |
| `supivpn_owner` | NOLOGIN; stable owner of schemas and objects |
| VM runtime login | CONNECT, USAGE, DML; no DDL or owner membership |
| Public / agent / recovery Lambda logins | Separate exact grants; see [isolation](LAMBDA_ISOLATION.md#database-privileges) |
| Migration login | CONNECT and permission to SET ROLE to `supivpn_owner` |

Login role names are configurable; `supivpn_owner` is the current migrator contract.
The migrator runs `SET LOCAL ROLE supivpn_owner` inside its transaction.
Changing the deployment login does not change ownership of new tables.
Existing objects with another owner are rejected; there is no automatic `REASSIGN OWNED`.

In the dedicated database, the `supivpn` schema holds application tables and
`public` holds migration metadata. Combined VM runtime uses DML and SELECT on
metadata, with owner-managed default privileges. Isolated Lambda roles must not
receive blanket DML/default grants: the migrator installs their exact table,
column and function permissions. Remove unnecessary PUBLIC CONNECT/TEMP/CREATE
permissions and grant required privileges explicitly.

An AWS RDS administrator is not a full PostgreSQL superuser. Role provisioning
must respect these restrictions and leave RDS service roles unchanged.
The migrator checks SET ROLE permissions before DDL.

## Connections and secrets

Runtime supports:

- `SUPIVPN_DATABASE_URL`, supplied by a secure deployment mechanism.
- An AWS adapter that retrieves the password from Secrets Manager before each
  new physical connection.

Never put credentials in client profiles, Lambda ZIPs, logs, or public outputs.
Public, agent, recovery and migrator credentials/secrets must be separate.
Database password and secret updates are not atomic; rotation needs a coordinated order.

Remote databases require TLS. The optional `database_tls` configuration keeps
`require` as the default; `verify-full` also authenticates the server. It supports
a separate `server_name` for a connection through a DNS alias and a `ca_file`
trust bundle. See [settings, precedence and examples](POSTGRES.md#configurable-database-tls).
Plaintext is allowed only for literal loopback addresses in local tests.

Limit total connections based on VM count or Lambda concurrency.
The current runtime pool allows at most four connections per process/warm
execution environment. RDS Proxy is not a SupiVPN dependency.
See [reconnect, TLS, and timeouts](POSTGRES.md#connections-and-migrations).

## Deployment order

1. Create the database, roles, schemas, grants, credentials, and network access.
2. Run `supivpn-migrate` with the migration identity in the deployment pipeline.
3. Wait for successful migration completion before starting/updating the controller.
4. Verify readiness and SAML scenarios.

This is the order for a fresh deployment. Isolated Lambdas require schema 9 and
a controlled cutover from the combined function; follow [upgrade and rollback](LAMBDA_ISOLATION.md#upgrade-and-rollback).
Migration is transactional; after commit, roll back only to a compatible runtime,
without automatic down migrations.

Controller startup performs no DDL. The migrator applies SQL under an advisory
lock, checks versions/checksums, and can compare the embedded migration digest
with the expected deployment digest. Ambiguous SQL outcomes are not silently retried.

HA needs an available writer endpoint and tested database failover.
Clients use the writer hostname, not a pinned IP.
[Integration tests](POSTGRES.md#running-integration-tests) use only a
disposable local database and do not replace provider failover testing.
