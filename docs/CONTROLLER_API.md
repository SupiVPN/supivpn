# Separate controller: VM and Lambda

Both entrypoints use the same controller logic and agent API.
Deployment and network access are described in [controller/README.md](CONTROLLER.md).

| Binary | Purpose |
| --- | --- |
| `cmd/supivpn-controller` → `local/arm64/supivpn-controller` | Separate VM process: public HTTPS and private agent Unix socket |
| `cmd/supivpn-lambda` → `local/arm64/bootstrap` | Public SAML/profile API only |
| `cmd/supivpn-agent-lambda` → `local/arm64/bootstrap-agent` | IAM-authenticated agent API only |
| `cmd/supivpn-recovery-lambda` → `local/arm64/bootstrap-recovery` | Scheduled recovery and privileged operator protocol only |
| `cmd/supivpn-migrate` → `local/arm64/supivpn-migrate` | Separate migrations, without an HTTP endpoint |

`internal/controlruntime` assembles the same SAML handlers, group policy, and
PostgreSQL backend. HTTP/SAML and domain types are independent of API Gateway.
The agent runtime never accesses the database. A separate deployment step runs
migrations with a migration identity before controller startup.

## Configuration

Examples: [VM](../examples/controller.vm.example.json), [public Lambda](../examples/controller.lambda.example.json),
[agent Lambda](../examples/agent.lambda.example.json), [recovery](../examples/recovery.lambda.example.json).
AWS deployment must use separate IAM/database roles and concurrency:
[isolation and upgrade contract](LAMBDA_ISOLATION.md).
These templates use fictional hostnames/account/instance IDs. Public URL, metadata,
and group policy must agree across controllers. Public URL is an HTTPS origin or
a URL with the `/supivpn` prefix; Entity ID and ACS are derived from it.

- VM: `-config /etc/supivpn/controller.json`.
- Lambda: `SUPIVPN_CONTROLLER_CONFIG`, default `/var/task/controller.json`.
  REST deployments may set `SUPIVPN_CONTROLLER_JSON` and `SUPIVPN_GATEWAY_FORMAT=rest`.
  A separate Secrets Manager adapter fetches the runtime user's password for each
  new physical database connection; VM mode can operate without AWS secrets/SDK integration.
- Both: `SUPIVPN_DATABASE_URL`, delivered by secret provisioning.
  Never write its value to JSON or logs. Remote databases require TLS:
  `require` encrypts without CA/hostname verification; `verify-full` verifies both.
  Plaintext fallback is prohibited.
- Both: optional `database_tls` in controller JSON selects `mode` (`require` by
  default or `verify-full`), `ca_file`, and a separate `server_name` for DNS aliases.
  The same block is supported in migration JSON. See [TLS configuration and
  precedence](POSTGRES.md#configurable-database-tls).
- Run migrations separately as described in [POSTGRES.md](POSTGRES.md).
  Startup does not perform DDL. Isolated Lambdas first require schema-10 privilege
  validation; VM processes can start without database access,
  but readiness/new logins fail until connectivity recovers.
- One process/warm Lambda shares a pool of at most 4 connections.
  Requests have a 10-second timeout, or the shorter Lambda deadline.
- Group mode is mandatory. IP pools remain agent configuration;
  the controller returns the selected group name and authorization deadlines.

Public routes: `GET /healthz`, `GET /saml/metadata`,
`GET /login/{ticket}`, `GET /profile`, `POST /saml/launch`, `POST /saml/acs`.
All paths are relative to `public_url`, including its optional `/supivpn` prefix.
Launch discards the tile POST and returns a fixed 303 to `/profile`; it performs
no authentication, pending-state creation, or key access. It is available only
when profile downloads are configured and needs its own exact API route.
IdP requests remain SP-initiated, with browser binding, InResponseTo, and signature
verification. After committing an allow decision, ACS returns 202; denial returns
403. A 202 means agent application is pending, not that the tunnel is established.
In the separate profile flow, successful ACS returns 200 with an .ovpn attachment.
It uses the same SAML verification and a separate PostgreSQL backend without an
agent decision. See [single SAML app setup and limitations](PROFILES.md).

## Agent authentication

### VM

The Unix socket resides in a dedicated **0700** directory owned by the controller
UID; the socket itself is **0600**. Provisioning creates the directory, and the
controller creates the socket. Startup never removes an existing file/socket.
Normal shutdown removes its own socket; after a crash, stale socket cleanup must
first confirm that the process is stopped.

The controller checks the peer UID through the kernel: Linux SO_PEERCRED or
macOS LOCAL_PEERCRED. `agent_uid` is required; the example permits a privileged
agent with UID 0. An unprivileged agent may share the controller UID.
Other unprivileged UIDs cannot access the private directory/socket.

Node ID is set in local controller configuration. Headers/JSON cannot override it.
The HTTPS listener does not expose the agent API. The separate controller process
neither owns the OpenVPN management socket nor manages OpenVPN's lifecycle.

Server certificate/key/chain are read at startup. After TLS updates, deployment
must restart the controller service to load the new files.

### API Gateway → Lambda

Create each `POST /agent/v1/*` route **separately with AWS_IAM**.
The agent signs requests with SigV4. The adapter accepts identity only from
API Gateway-generated `requestContext.authorizer.iam` (HTTP v2) or
`requestContext.identity` (REST). HTTP headers/body do not define node identity.

`agent_principals` maps an **exact EC2 session STS assumed-role ARN** to node ID.
Role ARNs without a session, wildcards, and arbitrary session names are rejected.
Update the mapping when replacing EC2. The agent role trust policy must allow
only EC2 to assume it, preventing users from creating matching assumed-role sessions.

The adapter checks API ID, account, stage, domain, method/path, and exact route key.
Browser routes accept only the public URL hostname; agents may use a separate
hostname in `domains`. Catch-all `$default`/greedy routes are unsuitable.
Use root API mapping: payload 2.0 rawPath omits the API mapping prefix.

**Deployment requirement:** permit Lambda invocation only from the required
API Gateway; nodes receive execute-api permission, not lambda:InvokeFunction.
Do not create a Function URL. Checking event fields does not cryptographically
authenticate arbitrary payloads submitted directly to Lambda.

HTTPS proxy, origin protection, rate limits, concurrency, IAM, and configuration
delivery belong to deployment. The adapter alone does not prove that a request
passed through the chosen proxy. See [AWS requirements](CONTROLLER.md),
[HTTP API IAM](https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-access-control-iam.html),
and [Lambda integration format](https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-develop-integrations-lambda.html).

## Agent API contract

All requests use POST, Content-Type application/json, and bodies up to 8 KiB.
Unknown/duplicate/nested/null fields are rejected. Requests must not contain
`node_id`. `generation` is a required unique process generation; CID/KID are
non-negative integers. Retries do not extend the original deadline.

| Path | JSON fields besides generation | Success |
| --- | --- | --- |
| /agent/v1/rotate | previous_generation; empty only for initial registration | 204 |
| /agent/v1/heartbeat | optional ready: boolean; OpenVPN pair readiness, extends only an unexpired node lease | 204 |
| /agent/v1/register | cid, kid, ticket: base64url encoding of 32 random bytes | 204 |
| /agent/v1/fetch | cid, kid | 200 with decision; 204 if no decision is ready |
| /agent/v1/ack | decision_id, outcome: applied / denied / failed | 204 |
| /agent/v1/cancel | cid, kid | 204 |

Decisions contain decision_id, node_id, generation, cid, kid, group_name or
denial_reason, expires_at, session_expires_at, and session_unlimited.
Only explicit `session_unlimited=true` with the zero Go timestamp
`0001-01-01T00:00:00Z` means no deadline; agents accept this only when the effective
`session_seconds=0`. An omitted flag means false; missing session_expires_at is
rejected. The short delivery expires_at remains mandatory.
Legacy renewal/ticket_hash fields have been removed. Before a management command,
the agent rechecks all bindings, the live connection, and deadlines.
ACK is sent only for the command's actual result.

`session_seconds` accepts 60..43200 or explicit **0** for no local limit.
An omitted global value means 43200; an omitted/null group value inherits it.
A signed IdP deadline also limits mode 0. Without an IdP deadline, an unlimited
tunnel may retain stale access indefinitely; startup logs warn about this.
Expiry closes the tunnel; automatic client reconnect requires a new SAML login.
Existing tunnels are not renewed. The global connection limit defaults to 1,
with group overrides.

Heartbeat runs once every 15 seconds per node. Lease expiry does not release
slots without confirmed shutdown: [fencing contract](SESSIONS.md).
Only the recovery Lambda constructs the EC2 adapter. Its `SUPIVPN_RECOVERY_JSON`
sets an explicit node allowlist and `automatic_recovery`; public and agent cannot
perform recovery. Legacy combined-Lambda power flags are rejected.
StopInstances/StartInstances are limited to the exact deployment allowlist.
Only one node recovers at a time, with at most three Starts per cluster per hour;
shared heartbeat loss cannot authorize node stops. See the fencing contract.

409 means conflict/stale generation; 410 means unknown or completed/expired login;
503 means backend unavailable. An identical ACK may be retried after a lost reply.
Fetch 204 cannot keep a request pending indefinitely: the agent enforces its deadline.
Internal database errors and SAML bodies never appear in responses or logs.

The recovery Lambda advances recovery and performs bounded cleanup from its
exact EventBridge rule. Agent heartbeat performs no recovery work. With a
one-minute schedule, recovery takes several steps/minutes. Authorization enforces
expiry independently of cleanup.

## Verification and builds

The dated build, race/integration, vet, and dependency report is in
[SECURITY.md](SECURITY.md). Fencing/recovery fixes and regressions are in
[SECURITY_REVIEW.md](SECURITY_REVIEW.md).
Passing functional tests does not close the remaining findings.

Run the full suite with disposable local PostgreSQL using [POSTGRES.md](POSTGRES.md).
`TestRuntimeSAMLAcrossVMAndLambda` checks both login directions, controller
restart between redirect and callback, signed SAML, group selection, denial,
replay, and repeated ACK through a real Unix socket.

VM tests cover kernel UID, socket permissions, and listener restart while retaining
a separate mock management connection. They do not replace real VPN tunnel tests.
On September 17, additional tests covered the real agent HTTP client, management
ACK, IP allocation from a remote-controller decision, and denial without a group,
including REST adapter calls and controller restart.
Operators must test DNS, transport, and the full IdP → controller → VPN flow in
each deployment.

From the repository root:

```bash
go test -race ./...
go vet ./...
go mod verify
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -buildvcs=false -o local/arm64/supivpn-controller ./cmd/supivpn-controller
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -buildvcs=false -tags lambda.norpc -o local/arm64/bootstrap ./cmd/supivpn-lambda
```

`go run ./cmd/supivpn-package` packages bootstrap and client.ovpn.template without
a key. Deployment provides metadata at `idp_metadata`, for example through a
Lambda layer. To bundle XML, pass `-metadata /path/to/idp-metadata.xml` explicitly
and configure `/var/task/idp-metadata.xml`.
AWS deployment may supply JSON through environment variables.
Passwords, DSNs, and private keys are not included in the ZIP.
