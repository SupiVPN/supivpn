# PostgreSQL backend

`internal/postgres` implements shared storage for SAML logins and agent decisions.
It was verified against disposable local PostgreSQL **18.3** on September 16, 2026.

The dependency upgrade for v0.1.1 was also verified against PostgreSQL **18.6**
on October 9, 2026, including TLS reconnection after a real test-server restart.
See [DEPENDENCY_UPGRADE.md](DEPENDENCY_UPGRADE.md).
VM and Lambda controllers use the same backend.

For Debian operators, see [PostgreSQL outside the VPN VM](REMOTE_DATABASE.md):
private networking, verified TLS, separate identities, first-time setup and a
controlled move of an existing database.

## Contract

`Store` implements `controller.Backend`; HTTP/SAML logic is shared with SupiVPN.
State progresses through `pending → started → decided → acknowledged`.
Disconnect changes the record to `cancelled`; every operation checks expiry,
independently of cleanup.

- `RotateNode`: registers or atomically changes the agent generation. The old
  generation can no longer register logins or fetch/acknowledge decisions.
  Retrying a completed rotation is safe; reusing an old generation name is forbidden.
- `Register`: binds a random ticket to node ID, generation, and CID/KID.
  Retries neither change the ticket nor extend its 30–180-second lifetime.
- `Start / Lookup`: one-time binding of AuthnRequest and browser-cookie hash.
  Any controller can read state created by another.
- `Complete`: rechecks snapshot and time under SQL locks, storing the assertion
  hash and immutable decision in one transaction. Repeated callbacks and assertion
  reuse are rejected.
- `Fetch`: returns the same decision until ACK, only to its agent and within the
  delivery deadline.
- `Acknowledge`: stores the actual `applied / denied / failed` outcome.
  An identical repeated ACK is allowed even after delivery expiry;
  conflicting outcomes cannot overwrite it.
- `Cancel / Prune`: reject late replies and perform bounded cleanup.
  Login records remain for at least 24 hours after expiry; assertion hashes remain
  until their own expiry. Generation history is retained.

After committing an allow decision, HTTP returns **202**; denial returns **403**.
A stored decision does not confirm an established VPN tunnel.
The agent must verify its live CID/KID, generation, and deadlines, apply the
decision once, and ACK after receiving the management-socket response.
The network adapter is described in [RUNTIME.md](CONTROLLER_API.md).
Agent requests use authenticated transport; node ID must come from verified
agent identity, never arbitrary JSON.

The database contains no complete assertions, cookies, bearer tickets, or IP
reservations. It stores hashes, operational bindings, selected group, and deadlines.
Since schema 8, VPN login records also contain `username`: the exact verified
SAML NameID for agent logs (up to 1024 UTF-8 bytes; longer values are omitted
without changing authorization). It shares the login record's retention period
and enters database backups and logs; access policies must account for this
personal data. Limits and operator drop continue using `subject_hash`.
Profile download has separate login state and shared replay protection.
See the [profile issuance contract](PROFILES.md).

## Connections and migrations

The current schema is **10**: `010_runtime_queries.sql` checks heartbeat expiry
after acquiring the node row lock and makes cleanup expiry filters indexable.
It replaces two functions without changing their signatures, ownership or ACLs;
there are no table rewrites, new indexes or data backfills.
`009_component_isolation.sql` adds restricted SQL
functions for separate Lambda roles. See [privileges and cutover](LAMBDA_ISOLATION.md).
`008_audit_username.sql` adds audit username with an
empty default for existing records, without changing active grants.
`007_safe_recovery.sql` adds maintenance, request receipts, power reservations,
and the Stop budget. `006_session_expiry.sql` removes session renewal;
`session_unlimited=true` with NULL `session_expires_at` explicitly marks an
unlimited grant. Finite grants always have deadlines. Subject hashes, leases,
fencing, and automatic node recovery remain. Cleanup never deletes potentially
active grants, including after indefinitely long sessions.
For the earlier 7 → 8 transition, first install a controller supporting both schemas, then
migrate and update agents. Schemas ≤6 need a separate procedure:
[sessions and upgrades](SESSIONS.md). Readiness rejects unknown future schemas.

`pgx/v5 v5.11.0`, direct PostgreSQL without RDS Proxy.
Each instance has at most 4 connections, minimum 0; idle timeout 1 minute,
lifetime 30 minutes plus up to 5 minutes of jitter.
Connect/statement timeout: 5 seconds; lock timeout: 2 seconds.
With `sslmode=require` and no `sslrootcert`/`PGSSLROOTCERT`, TLS ≥ 1.2 is
mandatory but CA/server-name verification is disabled. This encrypts traffic
without authenticating the server. Explicit `sslmode=verify-full` remains
supported; plaintext fallback is forbidden. Plaintext is allowed only for a
literal loopback IP in local tests.
Configure database-role limits and Lambda concurrency separately in deployment.

### Configurable database TLS

Controller JSON (VM or Lambda, including `SUPIVPN_CONTROLLER_JSON`) and the
migrator's `-config` JSON accept the same optional `database_tls` block:

```json
"database_tls": {
  "mode": "require"
}
```

`require` remains the default for AWS-generated connections and for an empty
block or omitted `mode`. It requires encryption but does **not** authenticate
the database server: an active network/DNS attacker can impersonate it. Choose
`verify-full` to verify the trusted CA, certificate validity and server identity:

```json
"database_tls": {
  "mode": "verify-full",
  "ca_file": "/etc/supivpn/db-ca.pem",
  "server_name": "writer.example.test"
}
```

| Setting | Behavior |
| --- | --- |
| `mode` | `require` or `verify-full`; empty means `require`. Other values fail configuration validation. |
| `ca_file` | Absolute path to a readable PEM CA bundle. Empty in `verify-full` uses the process system trust store. RDS deployments must supply the appropriate RDS CA bundle. |
| `server_name` | Optional exact DNS name or IP from the database certificate. Empty verifies the connection hostname. A nonempty value enables a separate TLS identity for DNS aliases; wildcards, URLs and host:port values are rejected. |

For example, connect to `db.example.test` through its CNAME but set `server_name`
to the actual managed database endpoint. The connection hostname stays unchanged;
only certificate verification and TLS SNI use `server_name`. Provision this name
from trusted configuration, never discover the expected identity by following
untrusted DNS answers. No AWS-specific DNS suffix is required by the product.

The block is authoritative for TLS mode and CA, overriding DSN `sslmode` /
`sslrootcert` and their environment defaults. Do not duplicate TLS policy across
both sources. With the block absent or null, existing explicit DSN settings are
preserved, including `verify-full`; existing local loopback tests can still use
`sslmode=disable`. In DSN-only migration mode, TLS is configured in the DSN.
For an explicit block, plaintext fallback is never enabled, even on loopback.
Supplying `ca_file` or `server_name` with `require` is an error, not an ignored
security setting. Missing/invalid CA files and failed certificate checks never
fall back to `require` or plaintext. Configuration errors do not include the DSN.

CA files contain public certificates only and are deployment inputs, not files
automatically downloaded by the controller. Supply the same trust bundle to the
controller and migrator (their filesystem paths may differ). Lambda can use a
deployment-managed layer with an absolute `/opt/...` path. Keep credentials out
of the block. Trust is loaded when the pool is created; after changing a CA
bundle or expected server name, restart/redeploy the controller. Renewed server
certificates with the same trusted CA and identity are accepted on reconnect.
Database replacement may require updating both the CNAME and `server_name`.

`TestDatabaseTLSHandshakeAndReconnect` exercises real pgx TLS handshakes against
an isolated loopback protocol stub: valid identity, wrong CA/name, expiry,
plaintext refusal, certificate renewal and rejection after reconnect.
`TestDatabaseTLSAliasResolvesOnEveryConnection` verifies that reconnect resolves
the connection alias again while retaining the independently configured TLS name.
These checks require no cloud access and do not replace live database failover tests.
The PostgreSQL 18 integration suite also runs `TestPostgresVerifiedTLSReconnect`:
queries and reconnect through a loopback TLS endpoint with verified chains, plus
rejection of a mismatched expected name before reaching the disposable database.

### Reconnect and migrations

The pool does not require database availability during startup. `Ready` returns
false until connectivity recovers; later requests reuse the same pool.
Before handing out each connection, `PrepareConn` checks `transaction_read_only`
with a 2-second timeout. Broken/read-only connections are closed; pgxpool tries
another or creates one before application SQL is sent.
New connections resolve the writer hostname again and verify read-write mode.
Never replace the writer hostname in configuration with its IP.
Pool health checks run every 15 seconds, but reconnect does not wait for that timer.

This recovers connections, not interrupted transactions. SQL/COMMIT errors fail
the call; uncertain commits are never retried silently. Repeated Fetch/ACK uses
the same ID rather than creating new authorization. Outages do not extend pending
request or VPN session deadlines.

`cmd/supivpn-migrate` is a separate tool run by deployment before controller
startup/update. AWS mode `-config /etc/supivpn/migrate.json` receives connection
parameters and a secret ARN, reading the `supivpn_migrator` password through the
EC2 IAM role into process memory only. Other platforms use `SUPIVPN_DATABASE_URL`;
using both sources is rejected. DSNs and SDK/pgx errors are not logged.
SQL runs transactionally under an advisory lock; repeated runs verify version
and checksum. Modified applied SQL and unknown versions are rejected.
Controller startup never runs migrations. `Ready` verifies schema availability;
it is not an agent/OpenVPN health check.

Deployment prepares NOLOGIN `supivpn_owner`, runtime/migrator logins, credentials,
grants, and default privileges according to the [database contract](DATABASE.md).
Runtime has DML on `supivpn` and metadata SELECT in `public`, without CREATE/TEMP,
DDL rights, or owner membership.

The CLI calls `MigrateAsOwner`: after the advisory lock it runs
`SET LOCAL ROLE supivpn_owner`. Created objects belong to a stable role even
when the administrator login changes. Objects in `supivpn` or migration metadata
or SECURITY DEFINER functions with a different owner are rejected before DDL; there is no automatic
`REASSIGN OWNED`. Initial `001_auth.sql` remains unchanged, preserving its checksum.

On RDS, the administrator remains NOSUPERUSER; Terraform creates a separate
NOINHERIT `supivpn_migrator` login with `supivpn_owner` membership.
Runtime lacks that membership. Bootstrap order: **database preparation → migrations
→ controller**. The schema-9 Lambda split requires a controlled cutover and three
restricted runtime logins; it cannot be applied as a single ZIP replacement.
The migrator uses one transaction with a 3-second lock timeout and 10-second
statement timeout. A confirmed committed migration is not automatically reverted.
When its outcome is unknown, rerunning the same migrator checks ledger/checksum;
runtime rollback is allowed only to a version compatible with the applied schema.
Deployment may pass `-expected-schema-sha256`, verify embedded SQL against current
files, and stop deployment on migration failure. Initial database readiness is
retried for up to 90 seconds; SQL is not automatically retried after migration begins.

## Migration authoring policy

Prefer backward-compatible migrations whenever possible. The intended sequence is:

1. **Expand:** add optional columns/tables or safe defaults while preserving existing
   reads and writes. If the previous controller rejects the future schema number,
   first ship and deploy a bridge release tested with both schemas. Keep the
   readiness schema allowlist and `CompatibleSchemaDigests` explicit and tested.
2. **Transition:** deploy readers/writers that handle the old and new representation.
   Backfill data in bounded, restartable batches when needed. Do not put an unbounded
   rewrite into the current single-transaction migrator or weaken its timeouts;
   a long-running backfill needs a separately reviewed mechanism.
3. **Contract:** only in a later release, after old components are gone and the
   rollback window has closed, remove obsolete structures or tighten constraints.
   Direct renames, drops, type changes, and new mandatory fields must not break
   components still running during a rolling update.

Compatibility includes authorization, active grants, replay protection, leases,
fencing state, and recovery behavior, not just whether SQL queries succeed. Never
retain an unsafe behavior to preserve compatibility; document the required breaking
change and maintenance procedure instead. Additive DDL can still take locks: review
its impact on heartbeat deadlines, table size, and timeouts.

Every schema-changing MR needs disposable PostgreSQL integration coverage for clean
bootstrap, upgrade from each supported schema, repeated migration/checksum checks,
the bridge release on both schemas, and the intended rollback version on the
post-migration schema. Exercise mixed old/new component behavior while rolling.
A new binary alone passing tests is not proof that the previous release can roll back.

Applied migration files are immutable; append a new numbered migration. Release
notes must state deployment order, supported schemas, lock/backfill impact, and the
last safe runtime rollback. Rollback normally restores compatible binaries and
leaves committed additive schema changes in place. Do not automatically reverse
committed DDL or restore an older database snapshot that could revive stale grants
or fencing generations. An incompatible change needs explicit maintenance and a
reviewed recovery procedure.

The v0.8.1 VM runtime supports schemas 7/8/9/10/11/12 for legacy authorization;
isolated Lambda components and opt-in profile features require 12.
Previously applied SQL migration files remain unchanged.

### Schema 11 to 12 (v0.8.1)

Migration 012 adds `owner_username` to issued profiles and short-lived import
grants. It fills existing profile labels from retained verified SAML login
records only when all available labels for that subject hash agree. It preserves
IDs, proof hashes, owner hashes, active/blocked states, revisions and timestamps.
Existing `.ovpn` files and OpenVPN settings do not change; no reissue is needed.

Unknown labels remain empty when no usable login evidence remains, including
never-used profiles and profiles whose login records have already been pruned.
After upgrade, a successful bound-profile SAML
admission fills that profile's empty label from verified NameID. A concurrent
row lock can defer that audit update until another login. Missing labels never
weaken owner checks or cause legacy fallback. New browser downloads and Connect
imports persist the label before delivering the file; no username is added to it.

Back up and verify restore procedures first. Prepare matching v0.8.1 binaries
and migration configuration before the maintenance window. Quiesce controllers,
all three Lambda components and recovery scheduling; drain VPN pairs when
heartbeat continuity cannot be maintained. Run the normal explicit migrator,
then reapply isolated runtime grants and start the matching binaries. Public
runtime gains UPDATE on `issued_profiles.owner_username` only, not on its proof,
subject hash, state or revision. Restricted SQL operators need SELECT on the
new column. Runtime startup performs no DDL or automatic grants.

The migration scans retained login records and the profile registry and takes
DDL locks. Existing 3-second lock and 10-second statement
timeouts apply; timeout rolls back the entire migration. Schedule it appropriately
for database size. Migration and role grants are separate transactions; a grant
failure must stop the deployment before traffic resumes.

v0.8.0 binaries reject schema 12. Mixed v0.8.0/v0.8.1 Lambdas are unsupported;
after commit, use only a verified schema-12-compatible build for runtime rollback.
Do not down-migrate or restore stale authorization state. The two-minor legacy
client transition remains unchanged (0.8.x and 0.9.x); it does not promise mixed
binary/schema versions. Check profile list/status and one existing bound profile
login after upgrade, then check block/reactivate with the current revision.

### Schema 10 to 11 (v0.8.0)

Migration 011 adds issued-profile ownership/state, login bindings and bounded
one-use import grants. Existing logins, decisions and replay state are retained;
old profiles are not assigned an owner retroactively. Upgrade controllers and
agents, migrate explicitly, and reapply isolated-role grants before enabling the
new profile mode. Profile ownership and Server URL refuse startup without schema
11. Follow the [two-port transition](PROFILE_BINDING.md) before issuing bound
profiles. v0.7.1 cannot be used for runtime rollback after migration; use a
verified schema-11-compatible build and keep committed authorization state.

### Schema 9 to 10

For VM deployments, first install this release's runtime while the database is
still on schema 9, then apply migration 010 with the migration identity and
verify readiness, SAML admission and heartbeat. The runtime's direct heartbeat
query enforces the new lock/expiry ordering on each supported schema.
For isolated Lambdas, use the [controlled cutover](LAMBDA_ISOLATION.md#upgrade-and-rollback):
old bundles reject schema 10 and new bundles reject schema 9.

Migration 010 is transactional and preserves logins, decisions, replay entries,
generation history and recovery budgets. Its function replacement uses the
existing migration lock/statement timeouts; if it cannot complete, stop the
deployment and retry the same migrator after resolving contention. Do not
increase timeouts automatically. v0.5.0 was the first runtime compatible
with schema 10; v0.4.5 cannot be used for rollback after that migration. Keep schema 10
and restore only a verified compatible runtime, without deleting migration
metadata or restoring old authorization state.

### Query costs and safety

Authenticated Fetch/ACK/Cancel operations use the transport-derived node identity
when acquiring the node lock, then compare it and its generation with the locked
login record. This removes a redundant node lookup while preserving node-before-login
lock ordering. Heartbeat uses one atomic statement; lease and fence checks run
after its node lock has been acquired. Writer checks on pool acquisition remain
mandatory, and uncertain SQL outcomes are not automatically retried.

Cleanup takes one database-clock cutoff per statement, allowing the existing
expiry indexes to bound scans. Entries that expire during that statement may
remain until the next batch. This does not extend authorization: admission and
delivery still check current database time, independently of cleanup. Batch
limits, `SKIP LOCKED`, replay retention and protection of potentially active
grants remain enforced.

## Running integration tests

Tests use the `integration` build tag; regular `go test ./...` does not contact
PostgreSQL. Integration rejects any address other than literal loopback and any
database other than `supivpn_test`; reset needs explicit environment authorization.

From `runtime`, using local Docker:

```bash
docker run --detach --rm --name supivpn-pg18-test \
  --publish 127.0.0.1:55432:5432 \
  --env POSTGRES_DB=supivpn_test --env POSTGRES_HOST_AUTH_METHOD=trust \
  --mount type=volume,destination=/var/lib/postgresql postgres:18.6-bookworm
docker exec supivpn-pg18-test pg_isready -U postgres -d supivpn_test
```

After `accepting connections` (for an optional IdP-specific test, replace
`/path/to/idp-metadata.xml` or omit `SUPIVPN_TEST_IDP_METADATA`):

```bash
SUPIVPN_TEST_POSTGRES_URL='postgres://postgres@127.0.0.1:55432/supivpn_test?sslmode=disable' \
SUPIVPN_TEST_POSTGRES_ALLOW_RESET=1 \
SUPIVPN_TEST_IDP_METADATA=/path/to/idp-metadata.xml \
go test -race -tags=integration -count=1 -timeout=300s ./...
# If running the restart test below, stop the container only after that test.
docker stop supivpn-pg18-test
```

The suite resets only the disposable test database. It checks signed SAML across
two controllers, replay, concurrent callbacks, foreign nodes, stale generations,
expiry after lock waits, lost replies, repeated ACK, cancellation, write-error
rollback, and migrations. It also checks broken idle/in-transaction connections,
read-only sessions, outages, startup without database availability, and DNS
resolution on reconnect.

TLS tests use a local fault endpoint with an untrusted in-memory certificate:
`require` encrypts, `verify-full` rejects the certificate, and `require` rejects
plaintext-only PostgreSQL. This endpoint's backend is disposable loopback PostgreSQL only.

`TestMigrationOwnerAndDefaultPrivileges` creates roles/grants under a local
NOSUPERUSER CREATEDB CREATEROLE administrator. It checks repeated migrations under
another login, ownership, no SET ROLE leakage beyond the transaction, runtime DML,
default privileges for new tables/sequences, and rejection of DDL, SET ROLE,
metadata changes, and mixed owners.

A real local PostgreSQL restart was also verified on September 16, 2026: the same
controller/pool recovered, decisions/replay protection survived, and ACK succeeded.
To repeat, leave the test container running and execute:

```bash
SUPIVPN_TEST_POSTGRES_URL='postgres://postgres@127.0.0.1:55432/supivpn_test?sslmode=disable' \
SUPIVPN_TEST_POSTGRES_ALLOW_RESET=1 SUPIVPN_TEST_RESTART=1 \
go test -race -tags=integration -run '^TestPostgresServerRestart$' -v -count=1 -timeout=90s ./internal/agent
```

After `READY_FOR_LOCAL_DB_RESTART`, in another terminal:

```bash
docker restart --timeout 1 supivpn-pg18-test
```

The test waits up to 45 seconds for restart. An anonymous volume preserves the
database across restart; final `docker stop` with `--rm` removes the container
and its anonymous volume. Do not use tmpfs for the restart test.
Runtime tests also cover VM ↔ Lambda adapters locally, including VM controller
restart. Cross-AZ RDS failover, deployed Lambda, and client UI require separate
deployment verification.

Build the migration tool without running it:

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build \
  -trimpath -buildvcs=false -o local/arm64/supivpn-migrate ./cmd/supivpn-migrate
```
