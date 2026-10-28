# Sessions, heartbeat, and fencing

Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
See [LICENSE](../LICENSE) for copyright ownership and licensing terms.

The limit counts concurrent VPN connections for one verified SAML user across
the whole cluster, including different nodes and groups.
Identity is SHA-256 of `issuer + NUL + NameID`; NameID must be stable and unique
within the IdP. This limits connections, not attested physical devices.

## Policy

Group changes and current revocation limits: [GROUPS.md](GROUPS.md).
Manual username-based tunnel drop and the deferred IdP suspend design:
[REVOCATION.md](REVOCATION.md). Automatic reaction to IdP events is not implemented.

`max_connections_per_user` defaults to **1**; a group may override it with 1–16.
For example:

```json
{
  "max_connections_per_user": 1,
  "session_seconds": 43200,
  "groups": [
    {"name": "admins-vpn", "priority": 10, "max_connections_per_user": 2},
    {"name": "engineers-production-vpn", "priority": 20, "session_seconds": 3600}
  ]
}
```

One group is selected by priority; limits from different groups are not added.
Reaching the limit rejects the **new** attempt (`connection_limit`), preserving
existing sessions. Reducing the limit does not disconnect existing devices.
An opposite-transport attempt for the same active profile can receive one
`connection_limit_retry` refusal followed by a bounded automatic retry;
[transport retry](TRANSPORTS.md#loss-of-an-established-udp-tunnel) describes its
fresh-SAML requirement and cluster-wide budget. This never grants an extra slot.

Global/per-group `session_seconds` accepts **60..43200 seconds**, default
**43200 (12 hours)**. Explicit **0** disables the local duration limit.
An omitted global JSON value keeps 12 hours; an omitted or `null` group value
inherits the global value. Group `0` means unlimited, not inheritance.
The selected group's policy determines both limits; controller and agent
configuration must agree.

The grant deadline is the minimum of the enabled local limit and all signed
`AuthnStatement.SessionNotOnOrAfter` values. The IdP cap **also applies to 0**.
`Conditions.NotOnOrAfter` and bearer confirmation define the short assertion
acceptance window, not VPN session duration.

**Unlimited-duration risk:** without an IdP session deadline, an existing tunnel
may retain access indefinitely after user removal, group/MFA policy changes, or
IdP browser-session expiry. Membership is not rechecked continuously.
Agents/controllers warn at startup. Revocation requires explicit VPN termination.
Connection limits, heartbeat, fencing, signatures, replay protection, and the
short login window remain enforced.

## TLS renegotiation

The server uses `reneg-sec 600 600`; issued client profiles use `reneg-sec 900`.
The server still initiates timed rekeys every ten minutes. The client interval
leaves time for that negotiation to finish before its independent timer fires.
This mitigates overlapping rekeys observed with OpenVPN Core 3.11.3; macOS
OpenVPN Connect 3.8.1 still requires validation with normal client traffic.
The browser authentication `hand-window 180` remains unchanged.

Existing imported profiles retain their old setting. Change only `reneg-sec 600`
to `reneg-sec 900` in the existing profile and reimport it to test the workaround.
Keep the existing tls-crypt-v2 block unchanged; no server-key rotation is needed.
This changes TLS rekey scheduling, not SAML authorization or the session deadline.
New downloads pick up the setting after deployment of a release containing the
updated template, including the copy packaged in the Lambda ZIP.

## Expiry and new login

In-place VPN session renewal has been removed. No browser opens before the
deadline; heartbeat, TLS renegotiation, and HTTP/ACK retries do not extend it.
At expiry, the agent sends OpenVPN `client-kill CID`; the server sends RESTART
to the client, which may reconnect automatically and start a **new** SP-initiated
SAML login. IP may change; existing TCP/SSH sessions break.
Password/MFA prompts depend on IdP policy and browser session; `ForceAuthn`
is not enabled. By default, each new VPN login first requires explicit confirmation
in the controller page, even if the IdP session could complete SSO without a prompt.
The operator can disable that step with `vpn_login_confirmation=false`, accepting
the risk that opening a relayed link can authorize someone else's VPN connection.
Only approve the login opened by your own OpenVPN Connect; see the
[configuration and login-link limitations](IDENTITY_PROVIDER.md#vpn-login-confirmation).

If the user does not complete the new login, no new VPN access is granted.
Old tickets/assertions/callbacks cannot restore the previous tunnel.
Expiring one user does not disconnect other users on the node.

The agent reconciles its CIDs with a complete OpenVPN `status 3` snapshot every
five seconds while connections exist. The local IP is released after
`DISCONNECT` or confirmed CID absence; the cluster slot after committed `cancel`.
Only numeric CIDs are retained from status; names and addresses are discarded.
Incomplete or invalid status closes management without releasing uncertain slots.
Neither deadline expiry nor successful kill proves tunnel closure. If a closing
CID is still present after 30 seconds, the agent stops its OpenVPN pair;
uncertain slots await confirmed restart/fencing.

Cancelling a client and immediately reconnecting can temporarily return
`connection_limit` if the first SAML authorization has already reserved a slot.
An unauthenticated attempt alone consumes no personal slot. In particular, a
silent UDP cancellation is not immediately visible to OpenVPN: handshake or
keepalive timeout must remove the old CID first. Reconciliation repairs missing
disconnect notifications; it does not shorten those transport timeouts or evict
another live session. Wait for the previous connection to close, then start a
fresh connection/login. Replaying the denied browser callback cannot reopen it.

PostgreSQL serializes concurrent slot allocation with a per-user advisory lock.
The grant reserves a slot before ACK: a lost response cannot allocate another slot.
Profile downloads use no slots. A new connection's `denied/failed` ACK releases
the reservation; `applied` requires confirmed CID removal followed by `cancel`, or fencing,
before reuse.

When every CIDR of the selected group **on this node** is exhausted, the agent
rejects the attempt (`pool_full`), preserves existing sessions, and acknowledges
failure to the controller. It never uses another group or node's pool.
Client/NLB selection of another node is not guaranteed.

## Client disconnection

A normal disconnect produces OpenVPN DISCONNECT, followed by agent cancel to the
controller. `client-kill` without confirmed DISCONNECT does not yet release the
local address. When client connectivity disappears, OpenVPN waits for keepalive
timeout; server `keepalive 10 60` means approximately 120 seconds.
Until failure is detected, a new attempt may be rejected because the slot is occupied.

After a confirmed disconnect, transient cancel failures are retried while the
agent generation's lease remains live. Retries back off up to 16 seconds; the
shared worker still makes at most four calls per second and keeps at most 32
jobs. Repeated cancellation is idempotent, including a response lost after commit.
The cluster slot remains occupied until cancellation commits. A temporary cancel
outage does not by itself stop unrelated live tunnels after 30 seconds.
This retry improvement is unreleased; v0.8.1 stops the pair after that deadline.

The delivery deadline for an uncertain applied ACK, the live-lease requirement,
generation checks and queue capacity remain enforced. Permanent API refusals or
exhausting the queue still stop the pair. If heartbeats also fail until the local
40-second lease expires, the agent stops; recovery then needs a clean restart of
the agent/OpenVPN pair or confirmed fencing. Merely restarting Lambda cannot
prove that an old VPN tunnel has stopped.

### Session limit after a controller update

A Lambda cold start does not invalidate live sessions. An `acknowledged` row is
not necessarily an occupied slot: only grants from the node's current generation,
without a confirmed stopped fence, count. A clean pair restart establishes a new
generation before releasing OpenVPN's startup hold. Historical rows may remain
`acknowledged` until cleanup without blocking reconnect on either node.

Use this read-only diagnostic query with an authorized operator connection. It
shows counts without usernames, profile secrets, login tickets or SAML data:

```sql
SELECT l.node_id, l.state, l.ack_result,
       l.generation = n.generation AS current_generation,
       n.fence_state,
       n.lease_expires_at > clock_timestamp() AS lease_live,
       count(*) AS rows,
       count(*) FILTER (
           WHERE l.generation = n.generation
             AND n.fence_state <> 'stopped'
             AND l.denial_reason = ''
             AND (l.ack_result IS NULL OR l.ack_result = 'applied')
       ) AS occupied_slots
FROM supivpn.logins l
LEFT JOIN supivpn.nodes n ON n.node_id = l.node_id
WHERE l.state IN ('decided', 'acknowledged')
GROUP BY l.node_id, l.state, l.ack_result,
         l.generation = n.generation, n.fence_state,
         n.lease_expires_at > clock_timestamp()
ORDER BY l.node_id, l.state;
```

For a current-generation slot, correlate `vpn.disconnected` with
`controller.request_retry` (`operation=cancel`) on the agent and
`agent.connection_cancelled` in the agent Lambda. A missing disconnect can mean
the daemon is still waiting for the transport timeout; inspect its complete
status before treating that tunnel as closed. After a heartbeat outage, check
that the old pair stopped and its supervised restart established a new generation.
If it cannot restart, use the verified shutdown/recovery procedure below.
Do not delete login rows or clear slots based only on their age or an expired
lease: doing so can admit an extra connection while the original tunnel survives.

## Heartbeat

The agent sends **one heartbeat per node every 15 seconds**, regardless of user
count. On Lambda this is a short synchronous IAM request; no per-session Lambda,
timer, or loop is created.

- The agent stops its pair unless it receives a timely extension within 40 seconds
  of starting its last successful heartbeat. Network calls do not hold the
  disconnect/expiry mutex; late replies cannot revive an expired lease.
- The database extends the node lease by 60 seconds using its own clock.
  An expired generation cannot renew its lease or receive new grants.
- **Lease or 12-hour session expiry does not release uncertain slots.**
  A frozen CPU may fail to stop OpenVPN locally.

Two continuously running nodes generate 345,600 heartbeat requests per 30 days,
plus login, ACK/cancel, retries, and scheduled cleanup.
The isolated agent Lambda performs no power operations during heartbeat.
The recovery Lambda performs one bounded step per schedule invocation, with a
30-second per-node cooldown and at most 3 seconds for recovery work.
The agent's shared worker is limited to four HTTP calls per second.
These are traffic bounds, not an absolute monthly spending cap.

## Confirmed shutdown and automatic recovery

The dedicated [recovery Lambda](LAMBDA_ISOLATION.md), configured with
`automatic_recovery: true` in `SUPIVPN_RECOVERY_JSON`, performs
**stop → confirmed stopped → start the same EC2 → healthy new generation**.
Public and agent components have no power driver or recovery database privileges.

- **One node at a time across the cluster.** PostgreSQL stores the state;
  controllers/Lambdas cannot start independent restart cycles.
- A new Stop requires another node with a ready OpenVPN management pair, at least
  30 seconds continuously healthy, and more than 30 seconds of lease remaining.
  Agents report readiness after checking management/PID; this is not an end-to-end
  VPN traffic, DNS, or routing probe. Recheck before every Stop.
- Shared heartbeat loss cannot initiate Stops without a witness. Before the first
  Stop reservation, observation can be cancelled safely after Power failure,
  witness loss, or clean generation change. Inspect does not block restart.
  After reservation, timeout no longer removes fencing.
- Stop uses Force and SkipOsShutdown, **without hibernation**: unsaved local data
  may be lost. Hibernation-enabled EC2 is unsupported.
  A successful Stop request alone does not release slots.
- Only a separate Describe confirming `stopped/terminated` permits old slots to
  stop counting. The old generation cannot revive.
- Start is allowed only when the controller recorded its own Stop attempt for
  that node. A node already stopped by an operator at first observation is not
  started. Old/removed nodes outside the deployment allowlist are observed only.
- **At most 3 StopInstances and 3 StartInstances per cluster per rolling hour**,
  including failed/unknown calls. At most 3 Stop requests per cycle; cooldown
  30 seconds. Budgets are persisted before cloud calls and survive controller restart.
- EC2 `running` is insufficient: a **new generation**, live lease, and 30 seconds
  of stable healthy OpenVPN are required. The entire cycle has 10 minutes.
  Otherwise recovery becomes `blocked`, **blocking subsequent automatic stops
  across the cluster**. Exhausting cycle attempts has the same effect.
  An operator must investigate and confirm safe recovery before resetting this
  state; there is no unlimited automatic retry.

Stop/Start permissions cover exact current SupiVPN EC2 ARNs only.
TerminateInstances is not granted. Unknown IDs, missing records, and API errors
do not prove shutdown. No recursive Lambda invocation or event publication is
needed to continue the cycle.

Heartbeat does not reconcile recovery in the isolated Lambda deployment.
An EventBridge schedule runs **once per minute**, doing one bounded step;
configure bounded/no async retries and exact source permissions.
That adds 43,200 scheduled invocations per 30 days. It may complete Start for a
node confirmed stopped by the controller even if other nodes have since failed.
Failover includes expiry, cooldown, and EC2 stop/start time, potentially minutes.
Database/EC2 errors cannot authorize unsafe slot reuse.
Deployment must connect the `recovery-blocked` alarm to a monitored notification
destination. CloudWatch alarms without configured actions do not notify operators.

Core depends on `postgres.Fencer` / `postgres.RecoveryDriver`; EC2 SDK is used
only by the AWS adapter. A VM controller without a provider adapter has no
automatic cloud fencing/recovery. `automatic_recovery=false` disables Start,
retaining the same orchestrator, witness, locks, and budgets.
It is not a maintenance switch. Planned work uses durable maintenance; recovery
from blocked requires an explicit verified operator operation.
Contract: [docs/RECOVERY.md](RECOVERY.md).

## Upgrades and verification

The upcoming v0.9.0 controller requires **schema 12** and bound profiles for
both VM and Lambda deployments. The older v0.8.1 VM controller supports
**schemas 7/8/9/10/11/12**; its isolated Lambda components and opt-in profile
features require **schema 12** (v0.8.0 uses 11).
Migration 012 adds persistent operator-visible owner labels without changing
profile proofs or session authorization; existing profiles need no reissue.
Migration 011 adds the profile registry, session binding and one-use import grants;
follow the [profile ownership upgrade guide](PROFILE_BINDING.md). Migration 010 rechecks heartbeat expiry after row-lock
waits and improves cleanup queries without releasing active grants.
Migration 009 adds restricted SQL functions and separate
role grants. A combined-Lambda deployment requires the [controlled cutover](LAMBDA_ISOLATION.md#upgrade-and-rollback).
`008_audit_username.sql` adds verified NameID for logs; session accounting still
uses `subject_hash`. `007_safe_recovery.sql` adds durable maintenance, operator
request receipts, power reservations, and the Stop budget.
`006_session_expiry.sql` removes old renewal records/column and adds an explicit
unlimited-grant flag. Earlier SQL migrations remain unchanged for checksum
verification. User accounting, leases, fencing, and bounded recovery remain.

Initial deployment applies all migrations in order.
For 7 → 8, first install a controller compatible with both schemas, check readiness,
then migrate and roll agents. On schema 7, username is not persisted; grants,
slot accounting, and heartbeat work. Successful migration does not terminate
existing grants. A strict schema=7 controller cannot be used for rollback after
migration. Schemas ≤6 need a separate maintenance window stopping old agents,
controller, and recovery scheduler.
Controller 8 supports old agents: it sends `username` only with explicit
`include_username=true`. New agents require the updated controller.

`make integration` checks concurrent slot allocation, lost ACK/cancel, migrations,
unlimited sessions, expiry without unsafe release, fencing, and recovery.
The restricted-role tests cover both Lambda gateway formats, handler replacement,
90-second cancel outages, lost committed replies, short whole-API outages and
clean generation restart after lease expiry. These are local fault-injection
tests with PostgreSQL; they do not deploy or update live Lambda functions.
Unit/race checks cover group duration, omitted/0/null configuration, signed IdP
deadlines, expired IdP rejection, TLS rekey without extension, heartbeat, and
isolation when terminating one user.
Native OpenVPN verifies real DISCONNECT and new SAML after expiry.
Operators verify automatic browser opening and the specific Connect UI with
[CONNECT_TEST.md](CONNECT_TEST.md).
AWS APIs are mocked; real Stop/StartInstances and failover also require operator
verification before production.
