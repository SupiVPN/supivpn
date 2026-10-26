# Temporary profile administration for Lambda

Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
See [LICENSE](../LICENSE) for licensing terms.

**Profile binding: v0.8.0; owner labels: v0.8.1 / schema 12.** The local
[`supivpn-cli`](CLI.md) requires a combined Debian node/controller host. It
cannot administer Lambda or a split deployment. The existing restricted recovery
operator invocation can handle profile status/block/activate if you have already
deployed that path; it is not a public administration endpoint.

Until a dedicated cloud CLI exists, an authorized database operator can block
one profile with the following procedure. These are manual instructions:
the development agent must not execute them against a working database.

## Prerequisites

Use your approved private database connection path and existing secret-loading
mechanism. Verify the target database/environment and use TLS `verify-full`
with its trusted CA (or the approved local connection path on the DB host).
Do not put passwords in shell arguments/history, URLs, tickets or copied output.
Do not expose PostgreSQL publicly for this procedure.

Use `psql -X` with a protected connection service/password file, IAM credential
workflow, or your normal DB administration tooling. Do not use a public runtime
credential. The dedicated operator needs only:

- CONNECT to the intended database and USAGE on schema `supivpn`;
- SELECT on `profile_id,owner_username,state,revision,created_at` in `supivpn.issued_profiles`;
- UPDATE on `state,revision` in that table.

Provisioning that role is a separate administrative action. No SELECT on
`secret_hash` or `subject_hash`, DDL, superuser privileges, migration credentials
or changes to Lambda IAM/runtime grants are necessary.

## Identify and inspect

Find the opaque `profile_id` and verified SAML NameID directly in the registry:

```sql
SELECT profile_id, owner_username, state, revision, created_at
FROM supivpn.issued_profiles
ORDER BY created_at DESC, profile_id
LIMIT 100;
```

`owner_username` is personal audit data, not a credential or a new authorization
key. It may be empty for a pre-upgrade profile with no retained login evidence;
the next successful admission using that profile can fill it without reissuing
the file. Row-lock contention can defer filling until another login. See
[schema 12 migration](POSTGRES.md#schema-11-to-12-v081). Existing operator roles
need SELECT on the new column; they do not need permission to modify it.

Do not use Device ID as the authorization target: it is client supplied.

In psql, set the exact ID and inspect only nonsecret columns:

```sql
\set ON_ERROR_STOP on
\set profile_id 'svp1_0123456789abcdef0123456789abcdef'
SELECT profile_id, owner_username, state, revision, created_at
FROM supivpn.issued_profiles
WHERE profile_id = :'profile_id';
```

Exactly one row must match. No row means stop and verify the ID, database and
schema. Do not broaden the WHERE clause or use SELECT *.

## Block with an expected revision

Set `expected_revision` to the value just inspected. The example uses 1:

```sql
\set expected_revision 1
BEGIN;
SET LOCAL lock_timeout = '2s';
SET LOCAL statement_timeout = '5s';
UPDATE supivpn.issued_profiles
SET state = 'blocked', revision = revision + 1
WHERE profile_id = :'profile_id'
  AND revision = :'expected_revision'::bigint
RETURNING profile_id, state, revision;
COMMIT;

SELECT profile_id, owner_username, state, revision, created_at
FROM supivpn.issued_profiles
WHERE profile_id = :'profile_id';
```

Require **UPDATE 1**, a successful COMMIT and a post-commit `blocked` status.
UPDATE 0 means a missing profile or concurrent change; do not blindly retry.
A statement error aborts the transaction; use ROLLBACK before further work.
A lost connection during COMMIT has an unknown outcome: reconnect and inspect
before deciding what to do. The conditional update preserves a newer operator
decision even when concurrent transactions wait on the row lock.

For deliberate reactivation, first inspect the current blocked state/revision,
then use the same transaction with `SET state = 'active'` and that revision.
Do not delete the row, replace the proof/owner, decrement revisions, or edit
logins, slot reservations, node generations or session tables.

## Scope of the result

A committed block denies new admission through that profile. It does not kill an
already authorized tunnel, ban the user, prevent a fresh authorized profile
download or revoke legacy profiles. Current sessions require the existing
[local node termination procedure](REVOCATION.md), on every relevant node and
listener, after blocking IdP access when account-wide revocation is intended.
Do not claim immediate disconnection from a successful SQL UPDATE alone.
If the block races with an applied but unacknowledged authorization, the agent's
fail-closed acknowledgement rule can stop that whole listener and disconnect
other tunnels. Retain independent administrative access during revocation.

Record the target environment, opaque ID, old/new revisions, operator, time and
verified result in your protected operations record. Keep database credentials,
profile proofs, SAML assertions and owner hashes out of that record.
