# Isolated Lambda components

Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
See [LICENSE](../LICENSE) for copyright ownership and licensing terms.

AWS deployments use three fixed-purpose executables. There is no runtime mode
switch from public or agent processing to recovery. VM deployment remains a
combined process; it does not provide this process/IAM isolation.

| Component | Bundle artifact | Accepted traffic | Database login default |
| --- | --- | --- | --- |
| Public | `lambda/supivpn-lambda.zip` | SAML, profile download, metadata, health | `supivpn_public` |
| Agent API | `lambda/supivpn-agent-lambda.zip` | IAM-authenticated `POST /agent/v1/*` | `supivpn_agent` |
| Recovery | `lambda/supivpn-recovery-lambda.zip` | Exact EventBridge rule; optionally direct operator invocation | `supivpn_recovery` |

All ZIPs contain a `bootstrap` executable. Only the public ZIP contains
`client.ovpn.template`. Corresponding standalone binaries are `bin/bootstrap`,
`bin/bootstrap-agent` and `bin/bootstrap-recovery`. The release bundle is format
**3**. All three Lambdas in v0.8.0 require database schema **11** (v0.7.1 uses 10), as declared by
`release.json.lambda_components.<component>.required_schema`.

## Invocation and IAM

Use separate execution roles, database credentials/secrets, log groups, versions,
aliases and reserved concurrency for all three functions. Public and agent roles
must have **no EC2 power permissions, no permission to invoke recovery, no
permission to assume its role, and no access to its database secret**. Restrict
their Secrets Manager and KMS access to their own secrets. Only public profile
issuance needs the wrapping key; agent/recovery must not receive it or IdP metadata.
When assertion encryption is enabled, only public may read its separate SAML
recipient-key secret. Do not grant agent/recovery access to that secret or its
KMS key; they reject assertion-encryption configuration.

Route public API methods only to public, IAM agent methods only to agent.
Restrict each function's resource policy to the exact API, stage and methods
with SourceAccount/SourceArn. Disable function URLs and the default API endpoint
when using custom domains. Keep agent EC2 roles limited to execute-api invocation;
they must not directly invoke any Lambda. Event JSON is not authentication.

Recovery has no API Gateway integration or public URL. Its invocation policy
allows the exact EventBridge rule and separately authorized operator identities.
Move maintenance/status/resume/resolve tooling to its alias ARN. Set
`SUPIVPN_OPERATOR_CONTROL=1` there only when those operations are needed.
Recovery alone gets DescribeInstances and StopInstances; add StartInstances only
when automatic recovery is enabled. Scope Stop/Start to explicit current instance
ARNs, the configured region/account and deployment tags. Keep the code allowlist
and IAM resources synchronized during instance replacement. Old node IDs may
still be described to confirm termination; they must not be powered back on.

None of these components invokes another Lambda. Configure recursion protection,
bounded timeouts and bounded async event age/retries; do not wire failure
destinations or alarms back into an invocation loop.

## Configuration

Public uses [controller.lambda.example.json](../examples/controller.lambda.example.json).
Agent uses [agent.lambda.example.json](../examples/agent.lambda.example.json).
Each receives its own `SUPIVPN_CONTROLLER_JSON` (or
`SUPIVPN_CONTROLLER_CONFIG`) and `SUPIVPN_GATEWAY_FORMAT=rest` for REST API.
HTTP API payload v2 is also supported. Keep their public_url/pending_seconds
consistent; agent needs public_url to validate the gateway contract, not to
perform SAML. The agent configuration must omit profile, IdP metadata and groups.
It alone needs the exact EC2 session principal-to-node mapping.

For encrypted assertions, public Lambda supports
`assertion_encryption.private_key_secret_arn` in v0.7.1 and later. It reads
AWSCURRENT at initialization and keeps the key in memory, with no disk copy or
automatic refresh in warm environments. Deliver only the matching public
certificate as a file. See the complete
[Secrets Manager configuration and rotation requirements](ASSERTION_ENCRYPTION.md#public-lambda-secrets-manager).

Recovery uses `SUPIVPN_RECOVERY_JSON`, with this structure:

```json
{
  "database_tls": {"mode": "require"},
  "node_ids": ["i-0123456789abcdef0", "i-0123456789abcdef1"],
  "automatic_recovery": true
}
```

Set `SUPIVPN_RECOVERY_RULE_ARN` to the exact scheduled rule ARN. Omitted/false
automatic_recovery disables Start, not Stop. The old combined-Lambda variables
`SUPIVPN_EC2_FENCING`, `SUPIVPN_EC2_RECOVERY`, `SUPIVPN_PRUNE_RULE_ARN`
are obsolete; enabled legacy recovery/operator flags on public/agent cause startup
failure rather than silently leaving fencing unconfigured.

All components accept either a securely supplied `SUPIVPN_DATABASE_URL`, or:

- `SUPIVPN_DATABASE_HOST`, `SUPIVPN_DATABASE_PORT`, `SUPIVPN_DATABASE_NAME`;
- its own `SUPIVPN_DATABASE_SECRET_ARN`, whose JSON is `{"user": "...", "pass": "..."}`;
- optional `SUPIVPN_DATABASE_USER` to override the component login default.
  Use a lowercase login with letters, digits and underscores; the secret user
  must match. Shared runtime, owner and migrator logins are refused in this mode.

Password reads use AWSCURRENT on every physical connection. Existing
[database TLS settings](POSTGRES.md#configurable-database-tls) apply to all three
configurations; require remains the default, and verify-full plus server_name/CA
can be enabled separately. Initialization has a 20-second deadline. Components
refuse to serve until schema and effective database privileges are validated.

## Database privileges

Use three distinct non-owner LOGIN roles with no role memberships and no
superuser, CREATEROLE, CREATEDB, REPLICATION or BYPASSRLS privileges. Remove
PUBLIC database CREATE/TEMP and schema CREATE; grant CONNECT explicitly.
Do not grant blanket table DML, sequence privileges or default DML privileges to
the isolated roles. Remove any inherited/default grants that widen this policy.

The migrator still assumes the stable NOLOGIN `supivpn_owner`; no RDS superuser
extension is required. Provision logins/passwords outside runtime. After migration,
`supivpn-migrate` installs the exact object grants when given either:

```text
-public-role supivpn_public -agent-role supivpn_agent -recovery-role supivpn_recovery
```

or `"runtime_roles": {"public":"supivpn_public","agent":"supivpn_agent","recovery":"supivpn_recovery"}`
in migration JSON. Supply all three or none; none retains VM deployment behavior.
Do not duplicate these same object grants in competing deployment resources.

| Data/control | Public | Agent | Recovery |
| --- | --- | --- | --- |
| Schema ledger | Read | Read | Read |
| Nodes, leases, generations | Read + row-lock helper | Read + bounded heartbeat/rotation functions | Read + fence/retry/health columns |
| VPN login mailbox | Read; authentication decision columns only | Read; registration columns and ACK/cancel state only | No direct access |
| SAML replay ledger | Read/insert | None | Bounded expiry cleanup function |
| Profile login state | DML | None | Bounded expiry cleanup function |
| Recovery state, budgets, maintenance, operator receipts | None | None | DML |
| DDL, role changes, grants | None | None | None |

Migration 009 adds four static SECURITY DEFINER functions owned by
supivpn_owner. They have a fixed safe search_path and no PUBLIC EXECUTE:
lock_node, agent_heartbeat, agent_rotate and prune_auth. Public cannot change
leases, generation, fencing status, maintenance or recovery budgets, including
through these functions. The agent cannot write authorization decisions or reset
recovery budgets. SQL cleanup cannot remove a potentially active unfenced slot.

Startup checks effective table/column/function/sequence privileges and refuses
missing or excess access, grant options, owner/admin credentials and role
assumption. Grant installation also clears stale column grants. Re-run deployment
validation after privilege changes; a warm process does not continuously audit
external DBA changes.

## Independent recovery and availability

Heartbeat updates only the lease/readiness and returns. It no longer performs
recovery from the agent Lambda. Recovery independently reads expired leases,
current generation, maintenance, recovery claim/operation, budgets and provider
power state. Immediately before reserving Stop it rechecks the lease under lock
and requires a healthy witness belonging to its own managed-node allowlist.
Start requires a prior Stop reservation and confirmed stopped state. Existing
single-node-at-a-time, three stops/starts per hour, blocked recovery and
idempotency guards remain; see [RECOVERY.md](RECOVERY.md).

For EventBridge `rate(1 minute)`, each invocation advances at most one step;
failure recovery can take several minutes, not one heartbeat period. Agents
still stop their OpenVPN pair after their local lease deadline. Slot reuse still
requires disconnect or confirmed fencing. Alarm if the schedule stops running
or a node remains blocked.

Reserve concurrency independently, including at least one agent slot and one
recovery slot. A starting point is public=2, agent=2, recovery=1; size from measured
latency/load and database capacity, not just node count. Each warm process can
hold four DB connections. Sum all components, deployment overlap, migrator and
operator headroom when setting DB role connection limits.

Reserved Lambda concurrency does not isolate shared API Gateway quotas, VPC
networking, Secrets Manager, PostgreSQL connections, CPU or locks. A compromised
public process can still forge authorizations (its inherent authority) or exhaust
shared database resources, but cannot directly instruct recovery or change its
lease evidence. Enforce connection/statement limits and monitor heartbeat latency.
This split does not claim complete availability isolation or protection after
compromise of recovery, agent API, database owner or AWS administrator.

## Upgrade and rollback

Migration 009 is additive and preserves sessions, replay entries and recovery
budgets. It does not make the previous combined Lambda deployment compatible.
Migration 010 replaces heartbeat and cleanup functions without changing their
signatures or privileges. Heartbeat checks lease expiry after acquiring the node
lock; cleanup uses indexable expiry cutoffs while preserving active grants.
The isolated Lambdas require schema 11. The VM executable in this release
supports schemas 7/8/9/10/11; `compatible_schemas` describes that bridge, not a waiver
of the Lambda component requirements.

For a fresh setup: provision roles/secrets/IAM -> migrate and install grants ->
start the three functions -> enable integrations/schedule -> check each boundary.

For a running combined Lambda, prepare a controlled cutover with the deployment
tooling before applying migration 009. Quiesce old integrations/invocations and
old recovery scheduling, remove old power privileges, migrate, provision new
restricted functions, then switch routes/operator alias and enable recovery.
If uninterrupted heartbeat cannot be guaranteed, drain/stop VPN pairs through
the existing maintenance procedure and expect client reconnects. Do not rely on
the active VPN connection as the only control path for that cutover.

For existing schema-9 or schema-10 isolated Lambdas, quiesce all three components
and the recovery schedule before applying all pending migrations through 011.
Reapply restricted role grants, then deploy the matching
schema-11 bundles and verify each boundary before resuming traffic. Use the
existing maintenance procedure to drain/stop VPN pairs if heartbeat continuity
cannot be maintained. Older bundles reject schema 11; a rolling mixture of
schema-10-only and schema-11-only Lambdas is not supported.

Migration and grant installation are separate transactions. A grant failure
must stop deployment; retry the reviewed migrator to verify the ledger and
reinstall grants. Never down-migrate, reset slots/generations, or restore the old
broad-privilege Lambda as an automatic rollback. Roll back only to an independently
verified schema-11/component-compatible artifact/configuration. Retain maintenance
and report an unconfirmed rollback instead of widening permissions.

Local checks cover distinct DB logins, forbidden SQL, the cross-role login/profile
flow, independent Stop/Start with a fake provider, lease changes during observation,
unmanaged witnesses, and overprivileged-role startup failure. Real IAM denial,
RDS permissions, API routing, independent concurrency, schedule cadence and
end-to-end IdP/VPN behavior still require deployment acceptance tests.

References: [AWS Lambda best practices](https://docs.aws.amazon.com/lambda/latest/dg/best-practices.html),
[Lambda concurrency](https://docs.aws.amazon.com/lambda/latest/dg/lambda-concurrency.html),
[PostgreSQL SECURITY DEFINER guidance](https://www.postgresql.org/docs/18/sql-createfunction.html).
